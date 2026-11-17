package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	ServerURL          string `json:"server_url"`
	DeviceID           string `json:"device_id"`
	DeviceToken        string `json:"device_token"`
	RustDeskPath       string `json:"rustdesk_path"`
	StatePath          string `json:"state_path,omitempty"`
	TLSCAFile          string `json:"tls_ca_file,omitempty"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitempty"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.ServerURL = strings.TrimSpace(cfg.ServerURL)
	cfg.DeviceID = strings.TrimSpace(cfg.DeviceID)
	cfg.DeviceToken = strings.TrimSpace(cfg.DeviceToken)
	cfg.RustDeskPath = strings.TrimSpace(cfg.RustDeskPath)
	if cfg.StatePath == "" {
		cfg.StatePath = filepath.Join(filepath.Dir(path), "managed-state.json")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) Validate() error {
	u, err := url.Parse(c.ServerURL)
	if err != nil || u.Scheme != "wss" || u.Host == "" {
		return fmt.Errorf("server_url must be a valid wss URL")
	}
	if c.DeviceID == "" || c.DeviceToken == "" {
		return fmt.Errorf("device_id and device_token are required")
	}
	if c.RustDeskPath == "" {
		return fmt.Errorf("rustdesk_path is required")
	}
	return nil
}
