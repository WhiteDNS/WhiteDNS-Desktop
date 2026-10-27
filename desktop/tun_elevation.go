package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"whitedns-desktop/internal/model"
)

const tunResumeFlag = "--whitedns-resume-tun"

var errTunElevationCancelled = errors.New("administrator request cancelled")

type tunResumeRequest struct {
	ParentPID        int                    `json:"parentPid"`
	CreatedAt        time.Time              `json:"createdAt"`
	OverrideSettings *model.SettingsProfile `json:"overrideSettings,omitempty"`
	PresetID         string                 `json:"presetId,omitempty"`
	PresetName       string                 `json:"presetName,omitempty"`
	Resolvers        []string               `json:"resolvers,omitempty"`
}

// Test seams never change the production UAC policy.
type tunElevationHooks struct {
	needed func() bool
	launch func(context.Context, string) error
	quit   func()
}

func (a *App) needsTunElevation() bool {
	if a.tunElevation != nil && a.tunElevation.needed != nil {
		return a.tunElevation.needed()
	}
	return tunElevationRequired()
}

func (a *App) requestTunElevation(ctx context.Context, settings *model.SettingsProfile, presetID, presetName string, resolvers []string) (model.AppState, error) {
	a.handleRuntimeState(model.RuntimeConnecting, "Waiting for administrator approval")
	err := a.relaunchTun(ctx, settings, presetID, presetName, resolvers)
	if errors.Is(err, errTunElevationCancelled) {
		a.handleRuntimeState(model.RuntimeDisconnected, "Administrator request cancelled")
		return a.GetAppState(), nil
	}
	if err != nil {
		a.handleRuntimeError(err.Error())
		a.handleRuntimeState(model.RuntimeFailed, err.Error())
		return a.GetAppState(), err
	}
	next := a.GetAppState()
	if a.tunElevation != nil && a.tunElevation.quit != nil {
		a.tunElevation.quit()
	} else {
		a.Quit()
	}
	return next, nil
}

func (a *App) relaunchTun(ctx context.Context, settings *model.SettingsProfile, presetID, presetName string, resolvers []string) error {
	// Persist selections before handing ownership to the elevated instance.
	// No profile links, keys, passwords, or resolver contents go on the CLI.
	a.mu.Lock()
	_, err := a.store.SaveState(a.state)
	a.mu.Unlock()
	if err != nil {
		return fmt.Errorf("could not save settings before requesting administrator access: %w", err)
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	file := filepath.Join(a.configDir, "tun-resume-"+hex.EncodeToString(nonce[:])+".json")
	request := tunResumeRequest{ParentPID: os.Getpid(), CreatedAt: time.Now().UTC(), OverrideSettings: settings, PresetID: presetID, PresetName: presetName, Resolvers: resolvers}
	raw, err := json.Marshal(request)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("could not prepare administrator request: %w", err)
	}
	defer os.Remove(file)
	defer os.Remove(file + ".ready")
	_, writeErr := f.Write(raw)
	closeErr := f.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		return err
	}
	launch := launchTunElevated
	if a.tunElevation != nil && a.tunElevation.launch != nil {
		launch = a.tunElevation.launch
	}
	return launch(ctx, file)
}

func readTunResume(file string, now time.Time) (*tunResumeRequest, error) {
	if !filepath.IsAbs(file) || filepath.Base(filepath.Dir(file)) != "WhiteDNS Desktop" {
		return nil, errors.New("invalid administrator resume location")
	}
	name := filepath.Base(file)
	if !strings.HasPrefix(name, "tun-resume-") || !strings.HasSuffix(name, ".json") {
		return nil, errors.New("invalid administrator request")
	}
	nonce := strings.TrimSuffix(strings.TrimPrefix(name, "tun-resume-"), ".json")
	if decoded, e := hex.DecodeString(nonce); e != nil || len(decoded) != 16 {
		return nil, errors.New("invalid administrator request")
	}
	info, err := os.Lstat(file)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil, errors.New("administrator request is missing or invalid")
	}
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var req tunResumeRequest
	if err := json.NewDecoder(io.LimitReader(f, 1<<20)).Decode(&req); err != nil {
		return nil, errors.New("invalid administrator request contents")
	}
	if req.ParentPID <= 0 || now.Sub(req.CreatedAt) > 2*time.Minute || req.CreatedAt.After(now.Add(5*time.Second)) {
		return nil, errors.New("administrator request expired")
	}
	return &req, nil
}

func prepareTunResume(args []string) (*tunResumeRequest, string, error) {
	if len(args) == 0 || args[0] != tunResumeFlag {
		return nil, "", nil
	}
	if len(args) != 2 {
		return nil, "", errors.New("invalid TUN resume arguments")
	}
	file := filepath.Clean(args[1])
	req, err := readTunResume(file, time.Now())
	if err != nil {
		return nil, "", err
	}
	if err := acceptTunElevation(req.ParentPID, file+".ready"); err != nil {
		return nil, "", err
	}
	_ = os.Remove(file)
	_ = os.Remove(file + ".ready")
	return req, filepath.Dir(file), nil
}

func (a *App) domReady(ctx context.Context) {
	if a.tunResume == nil {
		return
	}
	a.tunResumeOnce.Do(func() {
		req := a.tunResume
		go func() {
			a.mu.Lock()
			tun := a.state.TunnelMode == "tun"
			a.mu.Unlock()
			if !tun {
				a.handleRuntimeState(model.RuntimeFailed, "TUN mode was changed; select TUN and connect again")
				return
			}
			_, _ = a.startConnectionWithSettingsOptions(ctx, req.OverrideSettings, req.PresetID, req.PresetName, req.Resolvers)
		}()
	})
}
