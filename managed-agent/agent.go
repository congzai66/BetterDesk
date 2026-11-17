package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"sync"
	"time"
)

const managedCredentialWidget = "betterdesk.managed_credential"

type agentCommand struct {
	CommandID string          `json:"command_id"`
	WidgetID  string          `json:"widget_id"`
	Action    string          `json:"action"`
	Value     json.RawMessage `json:"value"`
}

type commandResult struct {
	Status string         `json:"status"`
	Result map[string]any `json:"result,omitempty"`
	Error  string         `json:"error_message,omitempty"`
}

type managedTimer interface{ Stop() bool }
type timerScheduler func(time.Duration, func()) managedTimer

type realTimer struct{ *time.Timer }

type CredentialAgent struct {
	statePath string
	applier   PasswordApplier
	commandMu sync.Mutex
	state     *managedState
	timer     managedTimer
	now       func() time.Time
	afterFunc timerScheduler
}

func NewCredentialAgent(statePath string, applier PasswordApplier) (*CredentialAgent, error) {
	state, err := loadManagedState(statePath)
	if err != nil {
		return nil, err
	}
	a := &CredentialAgent{statePath: statePath, applier: applier, state: state, now: time.Now}
	a.afterFunc = func(d time.Duration, fn func()) managedTimer {
		return realTimer{time.AfterFunc(d, fn)}
	}
	if state.Active {
		a.scheduleExpiryLocked(state.ExpiresAt, state.LastRequestID)
	}
	return a, nil
}

func (a *CredentialAgent) Close() {
	a.commandMu.Lock()
	defer a.commandMu.Unlock()
	if a.timer != nil {
		a.timer.Stop()
	}
}

func (a *CredentialAgent) ApplyCommand(ctx context.Context, cmd agentCommand) commandResult {
	a.commandMu.Lock()
	defer a.commandMu.Unlock()
	if cmd.CommandID == "" || cmd.WidgetID != managedCredentialWidget {
		return commandResult{Status: "error", Error: "unsupported managed credential command"}
	}
	if cmd.CommandID == a.state.LastRequestID {
		return commandResult{Status: "ok", Result: map[string]any{"applied": true, "idempotent": true}}
	}
	switch cmd.Action {
	case "rotate":
		return a.rotateLocked(ctx, cmd)
	case "revoke":
		return a.revokeLocked(ctx, cmd.CommandID)
	default:
		return commandResult{Status: "error", Error: "unsupported action"}
	}
}

func (a *CredentialAgent) rotateLocked(ctx context.Context, cmd agentCommand) commandResult {
	var value struct {
		Password  string `json:"password"`
		ExpiresAt string `json:"expires_at"`
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(cmd.Value, &value); err != nil || value.RequestID != cmd.CommandID {
		return commandResult{Status: "error", Error: "invalid rotation payload"}
	}
	if err := validateManagedPassword(value.Password); err != nil {
		return commandResult{Status: "error", Error: err.Error()}
	}
	expires, err := time.Parse(time.RFC3339, value.ExpiresAt)
	if err != nil || !expires.After(a.now().Add(30*time.Second)) || expires.After(a.now().Add(24*time.Hour)) {
		return commandResult{Status: "error", Error: "expiry must be between 30 seconds and 24 hours in the future"}
	}
	if err := a.applier.SetPassword(ctx, value.Password); err != nil {
		return commandResult{Status: "error", Error: err.Error()}
	}
	a.state.Active = true
	a.state.LastRequestID = cmd.CommandID
	a.state.ExpiresAt = expires.UTC().Format(time.RFC3339)
	if err := saveManagedState(a.statePath, a.state); err != nil {
		return commandResult{Status: "error", Error: "failed to persist credential expiry"}
	}
	a.scheduleExpiryLocked(a.state.ExpiresAt, cmd.CommandID)
	return commandResult{Status: "ok", Result: map[string]any{"applied": true, "expires_at": a.state.ExpiresAt}}
}

func (a *CredentialAgent) revokeLocked(ctx context.Context, requestID string) commandResult {
	if err := a.rotateToLocalRandom(ctx); err != nil {
		return commandResult{Status: "error", Error: err.Error()}
	}
	if a.timer != nil {
		a.timer.Stop()
		a.timer = nil
	}
	a.state.Active = false
	a.state.ExpiresAt = ""
	a.state.LastRequestID = requestID
	if err := saveManagedState(a.statePath, a.state); err != nil {
		// The password was already changed. Reporting success lets the server
		// remove its now-invalid vault copy; a stale state only causes a safe
		// extra local rotation after restart.
		log.Printf("managed credential state persistence failed after revocation: %v", err)
	}
	return commandResult{Status: "ok", Result: map[string]any{"applied": true}}
}

func (a *CredentialAgent) scheduleExpiryLocked(expiresAt, requestID string) {
	if a.timer != nil {
		a.timer.Stop()
	}
	expires, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		log.Printf("invalid persisted credential expiry; scheduling immediate local rotation")
		expires = a.now()
	}
	d := expires.Sub(a.now())
	if d < 0 {
		d = 0
	}
	a.timer = a.afterFunc(d, func() { a.expire(requestID) })
}

func (a *CredentialAgent) expire(requestID string) {
	a.commandMu.Lock()
	defer a.commandMu.Unlock()
	if !a.state.Active || a.state.LastRequestID != requestID {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if err := a.rotateToLocalRandom(ctx); err != nil {
		log.Printf("local credential expiry failed; retrying in one minute: %v", err)
		a.timer = a.afterFunc(time.Minute, func() { a.expire(requestID) })
		return
	}
	a.state.Active = false
	a.state.ExpiresAt = ""
	if err := saveManagedState(a.statePath, a.state); err != nil {
		a.state.Active = true
		a.state.ExpiresAt = a.now().UTC().Format(time.RFC3339)
		log.Printf("credential expiry state persistence failed; retrying local rotation: %v", err)
		a.timer = a.afterFunc(time.Minute, func() { a.expire(requestID) })
	}
}

func (a *CredentialAgent) rotateToLocalRandom(ctx context.Context) error {
	password, err := generateLocalPassword()
	if err != nil {
		return fmt.Errorf("generate local revocation password: %w", err)
	}
	return a.applier.SetPassword(ctx, password)
}

func generateLocalPassword() (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
	out := make([]byte, 32)
	max := big.NewInt(int64(len(alphabet)))
	for i := range out {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		out[i] = alphabet[n.Int64()]
	}
	return string(out), nil
}
