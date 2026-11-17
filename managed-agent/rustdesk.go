package main

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type PasswordApplier interface {
	SetPassword(ctx context.Context, password string) error
}

type commandRunner interface {
	Run(ctx context.Context, path string, args ...string) (string, error)
}

type execCommandRunner struct{}

func (execCommandRunner) Run(ctx context.Context, path string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, path, args...)
	configureHiddenCommand(cmd)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

type RustDeskPasswordApplier struct {
	Path   string
	Runner commandRunner
}

func (r *RustDeskPasswordApplier) SetPassword(ctx context.Context, password string) error {
	if err := validateManagedPassword(password); err != nil {
		return err
	}
	if r.Runner == nil {
		r.Runner = execCommandRunner{}
	}
	runCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	output, err := r.Runner.Run(runCtx, r.Path, "--password", password)
	if err != nil {
		return fmt.Errorf("RustDesk password command failed: %w", err)
	}
	// RustDesk prints Done only after its installed privileged service accepts
	// the IPC password change. Never include command output in logs or errors.
	if !strings.Contains(output, "Done!") {
		return fmt.Errorf("RustDesk did not confirm the password change; check installation, administrator rights, and password-change policy")
	}
	return nil
}

func validateManagedPassword(password string) error {
	if len(password) < 8 || len(password) > 128 {
		return fmt.Errorf("password length must be between 8 and 128 bytes")
	}
	for _, ch := range []byte(password) {
		if ch < 0x21 || ch > 0x7e {
			return fmt.Errorf("password must contain printable ASCII characters without spaces")
		}
	}
	return nil
}
