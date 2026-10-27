package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"whitedns-desktop/internal/model"
)

const tunnelProbeTimeout = 20 * time.Second

// Reuse the proxy/TLS connection across chart samples, without sharing it with
// country lookups or the manual ping button. Reset cancels in-flight requests
// and closes idle sockets when a connection ends.
type tunnelProbePool struct {
	mu     sync.Mutex
	key    tunnelProbeIdentity
	client *http.Client
	ctx    context.Context
	cancel context.CancelFunc
}

type tunnelProbeIdentity struct{ proxy, connectionID, user, password string }

func (pool *tunnelProbePool) reset() {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	pool.resetLocked()
}

func (pool *tunnelProbePool) resetLocked() {
	if pool.cancel != nil {
		pool.cancel()
	}
	closeHTTPClientIdleConnections(pool.client)
	pool.client, pool.ctx, pool.cancel, pool.key = nil, nil, nil, tunnelProbeIdentity{}
}

func (pool *tunnelProbePool) session(cfg runtimeProxyConfig, connectionID string) (*http.Client, context.Context, error) {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	key := tunnelProbeIdentity{proxy: cfg.cacheKey(), connectionID: connectionID}
	if cfg.Auth != nil {
		key.user, key.password = cfg.Auth.User, cfg.Auth.Password
	}
	if pool.client != nil && pool.key == key {
		return pool.client, pool.ctx, nil
	}
	pool.resetLocked()
	client, err := httpClientThroughProxyTimeouts(cfg, tunnelProbeTimeout, tunnelProbeTimeout)
	if err != nil {
		return nil, nil, err
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client.Transport.(*http.Transport).IdleConnTimeout = 30 * time.Second
	pool.ctx, pool.cancel = context.WithCancel(context.Background())
	pool.client, pool.key = client, key
	return pool.client, pool.ctx, nil
}

func (a *App) ProbeTunnelLatency() (model.CloudflarePingResult, error) {
	cfg, err := a.activeProxyConfig()
	if err != nil {
		return model.CloudflarePingResult{}, err
	}
	a.mu.Lock()
	connectionID := a.state.Runtime.ActiveConnectionID
	a.mu.Unlock()
	client, ctx, err := a.tunnelProbe.session(cfg, connectionID)
	if err != nil {
		return model.CloudflarePingResult{}, err
	}
	return measureTunnelLatency(ctx, client, proxyPingTarget, cfg.Address), nil
}

func measureTunnelLatency(parent context.Context, client *http.Client, target, proxyAddress string) model.CloudflarePingResult {
	result := model.CloudflarePingResult{Target: target, Proxy: proxyAddress}
	ctx, cancel := context.WithTimeout(parent, tunnelProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		result.Message = "Could not prepare the tunnel probe."
		return result
	}
	req.Header.Set("User-Agent", "WhiteDNS-Desktop")
	req.Header.Set("Cache-Control", "no-cache")
	started := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		var timeout net.Error
		switch {
		case errors.Is(err, context.Canceled):
			result.Message = "Tunnel probe cancelled because the connection changed."
		case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &timeout) && timeout.Timeout()):
			result.Message = "The test endpoint did not respond within the tunnel probe's timeout. Retrying through the tunnel."
		default:
			result.Message = "The test endpoint could not be reached through the tunnel. Retrying automatically."
		}
		return result
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, io.LimitReader(resp.Body, 1024)); err != nil {
		result.Message = "The test response was interrupted while travelling through the tunnel."
		return result
	}
	if resp.StatusCode != http.StatusNoContent {
		result.Message = fmt.Sprintf("The test endpoint returned HTTP %d instead of the expected 204 response. This does not necessarily mean the tunnel is disconnected.", resp.StatusCode)
		return result
	}
	result.OK, result.LatencyMs = true, time.Since(started).Milliseconds()
	result.Message = fmt.Sprintf("Tunnel response received in %d ms", result.LatencyMs)
	return result
}
