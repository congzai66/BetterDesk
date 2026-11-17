package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/coder/websocket"
)

type wireMessage struct {
	Type      string          `json:"type"`
	ID        string          `json:"id,omitempty"`
	Timestamp string          `json:"timestamp,omitempty"`
	Payload   json.RawMessage `json:"payload"`
}

type CDAPClient struct {
	cfg     *Config
	agent   *CredentialAgent
	conn    *websocket.Conn
	writeMu sync.Mutex
}

func (c *CDAPClient) Run(ctx context.Context) error {
	backoff := 5 * time.Second
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		err := c.runOnce(ctx)
		if err != nil && ctx.Err() == nil {
			log.Printf("CDAP connection ended: %v", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		if backoff < time.Minute {
			backoff *= 2
			if backoff > time.Minute {
				backoff = time.Minute
			}
		}
	}
}

func (c *CDAPClient) runOnce(ctx context.Context) error {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: c.cfg.InsecureSkipVerify} //nolint:gosec -- explicit opt-in for private test CAs only
	if c.cfg.TLSCAFile != "" {
		pem, err := os.ReadFile(c.cfg.TLSCAFile)
		if err != nil {
			return err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return fmt.Errorf("no certificates found in tls_ca_file")
		}
		tlsConfig.RootCAs = pool
	}
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}
	conn, _, err := websocket.Dial(ctx, c.cfg.ServerURL, &websocket.DialOptions{
		HTTPClient: httpClient, Subprotocols: []string{"cdap-v1"},
	})
	if err != nil {
		return err
	}
	c.conn = conn
	defer func() {
		conn.Close(websocket.StatusNormalClosure, "")
		c.conn = nil
	}()
	conn.SetReadLimit(1024 * 1024)
	if err := c.authenticate(ctx); err != nil {
		return err
	}
	if err := c.register(ctx); err != nil {
		return err
	}
	log.Printf("connected to BetterDesk as managed device %s", c.cfg.DeviceID)
	heartbeatCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go c.heartbeatLoop(heartbeatCtx)
	for {
		var msg wireMessage
		if err := readJSON(ctx, conn, &msg); err != nil {
			return err
		}
		switch msg.Type {
		case "command":
			var cmd agentCommand
			if err := json.Unmarshal(msg.Payload, &cmd); err != nil {
				continue
			}
			started := time.Now()
			result := c.agent.ApplyCommand(ctx, cmd)
			payload, _ := json.Marshal(map[string]any{
				"command_id": cmd.CommandID, "status": result.Status, "result": result.Result,
				"error_message": result.Error, "execution_time_ms": time.Since(started).Milliseconds(),
			})
			if err := c.writeJSON(ctx, "command_response", cmd.CommandID, payload); err != nil {
				return err
			}
		case "ping", "registered":
			// Keepalive and registration acknowledgement need no response.
		}
	}
}

func (c *CDAPClient) authenticate(ctx context.Context) error {
	payload, _ := json.Marshal(map[string]string{
		"method": "device_token", "token": c.cfg.DeviceToken,
		"device_id": c.cfg.DeviceID, "client_version": agentVersion,
	})
	if err := c.writeJSON(ctx, "auth", "", payload); err != nil {
		return err
	}
	var msg wireMessage
	if err := readJSON(ctx, c.conn, &msg); err != nil {
		return err
	}
	var result struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}
	if msg.Type != "auth_result" || json.Unmarshal(msg.Payload, &result) != nil || !result.Success {
		return fmt.Errorf("CDAP authentication failed: %s", result.Error)
	}
	return nil
}

func (c *CDAPClient) register(ctx context.Context) error {
	hostname, _ := os.Hostname()
	manifest := map[string]any{
		"manifest_version":   "1.0",
		"device":             map[string]any{"name": hostname, "type": "desktop", "vendor": "BetterDesk", "model": "RustDesk managed credential", "firmware": agentVersion, "linked_peer_id": c.cfg.DeviceID},
		"capabilities":       []string{"commands", "unattended_access"},
		"heartbeat_interval": 15,
		"widgets": []map[string]any{{
			"id": managedCredentialWidget, "type": "button", "label": "Managed temporary credential",
			"readonly": true, "permissions": map[string]string{"read": "admin", "control": "admin", "execute": "admin"},
		}},
	}
	payload, _ := json.Marshal(map[string]any{"manifest": manifest})
	return c.writeJSON(ctx, "register", "", payload)
}

func (c *CDAPClient) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			payload, _ := json.Marshal(map[string]any{"widget_values": map[string]any{}})
			if err := c.writeJSON(ctx, "heartbeat", "", payload); err != nil {
				return
			}
		}
	}
}

func (c *CDAPClient) writeJSON(ctx context.Context, messageType, id string, payload json.RawMessage) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return writeJSON(ctx, c.conn, &wireMessage{Type: messageType, ID: id, Timestamp: time.Now().UTC().Format(time.RFC3339), Payload: payload})
}

func readJSON(ctx context.Context, conn *websocket.Conn, target any) error {
	_, data, err := conn.Read(ctx)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, target)
}

func writeJSON(ctx context.Context, conn *websocket.Conn, msg *wireMessage) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return conn.Write(ctx, websocket.MessageText, data)
}
