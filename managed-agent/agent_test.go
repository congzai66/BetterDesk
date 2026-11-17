package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeApplier struct {
	passwords []string
	fail      bool
}

func (f *fakeApplier) SetPassword(_ context.Context, password string) error {
	if f.fail {
		return errors.New("simulated command failure")
	}
	f.passwords = append(f.passwords, password)
	return nil
}

type fakeTimer struct {
	fn      func()
	stopped bool
}

func (t *fakeTimer) Stop() bool { t.stopped = true; return true }

func TestManagedAgentRotateIdempotenceExpiryAndNoSecretPersistence(t *testing.T) {
	applier := &fakeApplier{}
	statePath := filepath.Join(t.TempDir(), "state.json")
	agent, err := NewCredentialAgent(statePath, applier)
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	agent.now = func() time.Time { return now }
	timer := &fakeTimer{}
	agent.afterFunc = func(_ time.Duration, fn func()) managedTimer { timer.fn = fn; return timer }

	password := "CorrectHorseBattery1234"
	expires := now.Add(15 * time.Minute).Format(time.RFC3339)
	value, _ := json.Marshal(map[string]string{"password": password, "expires_at": expires, "request_id": "request-1"})
	cmd := agentCommand{CommandID: "request-1", WidgetID: managedCredentialWidget, Action: "rotate", Value: value}
	result := agent.ApplyCommand(context.Background(), cmd)
	if result.Status != "ok" || len(applier.passwords) != 1 || applier.passwords[0] != password {
		t.Fatalf("unexpected rotation result: %+v, applications=%d", result, len(applier.passwords))
	}
	encodedResult, _ := json.Marshal(result)
	if strings.Contains(string(encodedResult), password) {
		t.Fatal("command response leaked the managed password")
	}
	stateBytes, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stateBytes), password) {
		t.Fatal("state file leaked the managed password")
	}
	again := agent.ApplyCommand(context.Background(), cmd)
	if again.Status != "ok" || len(applier.passwords) != 1 {
		t.Fatal("duplicate request was not idempotent")
	}
	if timer.fn == nil {
		t.Fatal("expiry timer was not scheduled")
	}
	timer.fn()
	if len(applier.passwords) != 2 || applier.passwords[1] == password || len(applier.passwords[1]) != 32 {
		t.Fatalf("expiry did not rotate to a new random local password: %d applications", len(applier.passwords))
	}
	reloaded, err := NewCredentialAgent(statePath, applier)
	if err != nil {
		t.Fatal(err)
	}
	defer reloaded.Close()
	if reloaded.state.Active || reloaded.state.LastRequestID != "request-1" {
		t.Fatalf("unexpected persisted state: %+v", reloaded.state)
	}
}

func TestManagedAgentRestoresFutureExpiry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	future := time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339)
	if err := saveManagedState(path, &managedState{Active: true, LastRequestID: "restart-1", ExpiresAt: future}); err != nil {
		t.Fatal(err)
	}
	agent, err := NewCredentialAgent(path, &fakeApplier{})
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()
	if agent.timer == nil {
		t.Fatal("active persisted credential did not restore its expiry timer")
	}
}

func TestManagedAgentRevokeUsesUnknownRandomPassword(t *testing.T) {
	applier := &fakeApplier{}
	agent, err := NewCredentialAgent(filepath.Join(t.TempDir(), "state.json"), applier)
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()
	result := agent.ApplyCommand(context.Background(), agentCommand{CommandID: "revoke-1", WidgetID: managedCredentialWidget, Action: "revoke", Value: json.RawMessage(`{}`)})
	if result.Status != "ok" || len(applier.passwords) != 1 || len(applier.passwords[0]) != 32 {
		t.Fatalf("unexpected revoke result: %+v", result)
	}
	encoded, _ := json.Marshal(result)
	if strings.Contains(string(encoded), applier.passwords[0]) {
		t.Fatal("revoke response leaked local random password")
	}
}

func TestRustDeskApplierRequiresDoneConfirmation(t *testing.T) {
	password := "CorrectHorseBattery1234"
	applier := &RustDeskPasswordApplier{Path: "rustdesk.exe", Runner: runnerFunc(func(_ context.Context, _ string, _ ...string) (string, error) {
		return "policy rejected " + password, nil
	})}
	err := applier.SetPassword(context.Background(), password)
	if err == nil || strings.Contains(err.Error(), password) {
		t.Fatalf("unexpected error: %v", err)
	}
}

type runnerFunc func(context.Context, string, ...string) (string, error)

func (f runnerFunc) Run(ctx context.Context, path string, args ...string) (string, error) {
	return f(ctx, path, args...)
}

func TestConfigRejectsPlaintextWebSocket(t *testing.T) {
	cfg := Config{ServerURL: "ws://example.test/cdap", DeviceID: "123456", DeviceToken: "secret", RustDeskPath: "rustdesk.exe"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("plaintext ws:// configuration was accepted")
	}
}
