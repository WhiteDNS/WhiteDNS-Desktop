//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

func tunElevationRequired() bool { return !windows.GetCurrentProcessToken().IsElevated() }

func launchTunElevated(ctx context.Context, requestFile string) error {
	return launchTunElevatedArgs(ctx, requestFile, nil)
}

func launchTunElevatedArgs(ctx context.Context, requestFile string, prefix []string) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, err := windows.UTF16PtrFromString(executable)
	if err != nil {
		return err
	}
	args := append(append([]string{}, prefix...), tunResumeFlag, requestFile)
	escaped := make([]string, len(args))
	for i, arg := range args {
		escaped[i] = syscall.EscapeArg(arg)
	}
	parameters, err := windows.UTF16PtrFromString(strings.Join(escaped, " "))
	if err != nil {
		return err
	}
	directory, err := windows.UTF16PtrFromString(filepath.Dir(executable))
	if err != nil {
		return err
	}
	// This is the application window the user is asking to open, not a
	// background shell. Windows owns the consent/credential dialog.
	if err := windows.ShellExecute(0, verb, file, parameters, directory, windows.SW_SHOWNORMAL); err != nil {
		if errors.Is(err, windows.ERROR_CANCELLED) {
			return errTunElevationCancelled
		}
		return fmt.Errorf("could not request administrator access: %w", err)
	}
	// The old UI stays alive until the new instance has read the one-shot
	// request and verified that it can resume. Cancel/failure never closes it.
	waitCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if raw, err := os.ReadFile(requestFile + ".ready"); err == nil && string(raw) == "ready" {
			return nil
		}
		select {
		case <-waitCtx.Done():
			return errors.New("administrator instance did not become ready; the current window remains open")
		case <-ticker.C:
		}
	}
}

func acceptTunElevation(parentPID int, readyFile string) error {
	if tunElevationRequired() {
		return errors.New("Windows administrator approval was not granted")
	}
	parent, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(parentPID))
	if err != nil {
		return errors.New("the original WhiteDNS window is no longer available")
	}
	defer windows.CloseHandle(parent)
	buffer := make([]uint16, 32768)
	size := uint32(len(buffer))
	if err := windows.QueryFullProcessImageName(parent, 0, &buffer[0], &size); err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	if !strings.EqualFold(filepath.Clean(windows.UTF16ToString(buffer[:size])), filepath.Clean(executable)) {
		return errors.New("administrator request did not come from this WhiteDNS executable")
	}
	if err := os.WriteFile(readyFile, []byte("ready"), 0600); err != nil {
		return err
	}
	// Wait for the old instance to finish scanner/runtime cleanup before the
	// elevated app opens the same state and runtime directories.
	result, err := windows.WaitForSingleObject(parent, 30000)
	if err != nil {
		return err
	}
	if result != windows.WAIT_OBJECT_0 {
		return errors.New("the previous WhiteDNS window did not finish closing")
	}
	return nil
}
