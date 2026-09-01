//go:build android

package main

import (
	"context"

	"cottendns-go/internal/client"
)

func canPromptStartup() bool { return false }

// Android consumers supervise the client process and consume its WD_* telemetry.
// Keep the interactive desktop TUI (and its terminal dependencies) out of the
// vendored Android executable regardless of TERMINAL_UI in a supplied config.
func runClient(ctx context.Context, app *client.Client, intro func()) error {
	intro()
	return app.Run(ctx)
}
