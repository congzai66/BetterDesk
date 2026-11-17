//go:build !windows

package main

import "context"

func runPlatform(run func(context.Context) error) error {
	return runContext(run)
}

func installPlatformService(_, _ string) error {
	return &platformError{}
}

func uninstallPlatformService() error {
	return &platformError{}
}

type platformError struct{}

func (*platformError) Error() string { return "service installation is supported only on Windows" }
