//go:build !windows

package main

import (
	"context"
	"errors"
)

func tunElevationRequired() bool { return false }
func launchTunElevated(context.Context, string) error {
	return errors.New("automatic TUN elevation is supported on Windows")
}
func acceptTunElevation(int, string) error {
	return errors.New("automatic TUN elevation is supported on Windows")
}
