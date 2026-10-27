package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func localProbeProxy(t *testing.T, connects *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT required", 400)
			return
		}
		upstream, err := net.DialTimeout("tcp", r.Host, time.Second)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		client, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			_ = upstream.Close()
			return
		}
		connects.Add(1)
		_, _ = fmt.Fprint(buffered, "HTTP/1.1 200 Connection Established\r\n\r\n")
		_ = buffered.Flush()
		defer client.Close()
		defer upstream.Close()
		go func() { _, _ = io.Copy(upstream, buffered); _ = upstream.Close() }()
		_, _ = io.Copy(client, upstream)
	}))
}

func TestTunnelProbeReusesProxyAndTLSConnection(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer origin.Close()
	var connects atomic.Int32
	proxy := localProbeProxy(t, &connects)
	defer proxy.Close()
	pool := &tunnelProbePool{}
	defer pool.reset()
	cfg := runtimeProxyConfig{Address: proxy.Listener.Addr().String(), Protocol: "http"}
	client, ctx, err := pool.session(cfg, "connection-one")
	if err != nil {
		t.Fatal(err)
	}
	client.Transport.(*http.Transport).TLSClientConfig = origin.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	for range 3 {
		result := measureTunnelLatency(ctx, client, origin.URL, cfg.Address)
		if !result.OK {
			t.Fatalf("proxy probe failed: %s", result.Message)
		}
	}
	if connects.Load() != 1 {
		t.Fatalf("expected one reused TLS connection, got %d", connects.Load())
	}
	same, _, err := pool.session(cfg, "connection-one")
	if err != nil || same != client {
		t.Fatal("chart samples did not reuse the client")
	}
	next, _, err := pool.session(cfg, "connection-two")
	if err != nil || next == client {
		t.Fatal("new session reused the old client's sockets")
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("old session was not cancelled")
	}
}

func TestTunnelProbeAllowsTLSHandshakeLongerThanLegacyFiveSeconds(t *testing.T) {
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	origin.TLS = &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) { time.Sleep(5200 * time.Millisecond); return nil, nil }}
	origin.StartTLS()
	defer origin.Close()
	var connects atomic.Int32
	proxy := localProbeProxy(t, &connects)
	defer proxy.Close()
	pool := &tunnelProbePool{}
	defer pool.reset()
	cfg := runtimeProxyConfig{Address: proxy.Listener.Addr().String(), Protocol: "http"}
	client, ctx, err := pool.session(cfg, "slow-tunnel")
	if err != nil {
		t.Fatal(err)
	}
	client.Transport.(*http.Transport).TLSClientConfig = origin.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	result := measureTunnelLatency(ctx, client, origin.URL, cfg.Address)
	if !result.OK || result.LatencyMs < 5000 {
		t.Fatalf("slow but working tunnel was rejected: %#v", result)
	}
}

func TestTunnelProbeReportsHTTPFailuresAndResetCancelsRequests(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) }))
	defer origin.Close()
	result := measureTunnelLatency(context.Background(), origin.Client(), origin.URL, "test-proxy")
	if result.OK || !strings.Contains(result.Message, "HTTP 403") {
		t.Fatal("HTTP error was disguised as a valid latency")
	}
	deadline, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	result = measureTunnelLatency(deadline, origin.Client(), origin.URL, "test-proxy")
	if result.OK || !strings.Contains(result.Message, "timeout") {
		t.Fatalf("timeout was not explained: %s", result.Message)
	}
	pool := &tunnelProbePool{}
	_, ctx, err := pool.session(runtimeProxyConfig{Address: "127.0.0.1:1", Protocol: "socks"}, "one")
	if err != nil {
		t.Fatal(err)
	}
	pool.reset()
	select {
	case <-ctx.Done():
	default:
		t.Fatal("reset did not cancel requests")
	}
}

func TestTunnelProbeNeverFallsBackToDirectWhenProxyFails(t *testing.T) {
	var requests atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(http.StatusNoContent) }))
	defer origin.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	for _, protocol := range []string{"http", "socks"} {
		pool := &tunnelProbePool{}
		client, ctx, err := pool.session(runtimeProxyConfig{Address: address, Protocol: protocol}, "closed-proxy")
		if err != nil {
			t.Fatal(err)
		}
		result := measureTunnelLatency(ctx, client, origin.URL, address)
		pool.reset()
		if result.OK || requests.Load() != 0 {
			t.Fatalf("%s probe bypassed the tunnel", protocol)
		}
	}
}
