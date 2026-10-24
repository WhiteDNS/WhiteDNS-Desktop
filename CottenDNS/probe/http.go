// Package probe verifies an actual authenticated CottenDNS tunnel and HTTPS
// egress. Credentials stay in memory or private temporary files, never argv.
package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"cottendns-go/internal/client"
	"cottendns-go/internal/config"
	"golang.org/x/net/proxy"
)

type Config struct {
	Domain    string      `json:"domain"`
	Key       string      `json:"key"`
	Resolvers []string    `json:"-"`
	Transport string      `json:"-"`
	URL       string      `json:"-"`
	TLSConfig *tls.Config `json:"-"`
}

// Result preserves the furthest observed stage, including when a later HTTPS
// operation fails. ErrorClass is bounded and never includes traffic metadata.
type Result struct {
	OK         bool
	Stage      string
	Handshake  bool
	HTTPStatus int
	ErrorClass string
}

type progress struct {
	mu        sync.Mutex
	stage     string
	connected bool
}

func (p *progress) mark(stage string) {
	p.mu.Lock()
	p.stage = stage
	p.mu.Unlock()
}

func (p *progress) connect() {
	p.mu.Lock()
	p.connected, p.stage = true, "socks"
	p.mu.Unlock()
}

func (p *progress) snapshot() (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stage, p.connected
}

type runtimeStoppedError struct{ class string }

func (e runtimeStoppedError) Error() string { return "Cotten client stopped before HTTPS completed" }

func classifyError(err error) string {
	if err == nil {
		return ""
	}
	var stopped runtimeStoppedError
	if errors.As(err, &stopped) {
		return stopped.class
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "deadline_exceeded"
	}
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	if errors.Is(err, syscall.EADDRINUSE) {
		return "address_in_use"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "connection_refused"
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return "connection_reset"
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return "connection_closed"
	}
	var certificate *tls.CertificateVerificationError
	if errors.As(err, &certificate) {
		return "tls_certificate_error"
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return "network_timeout"
	}
	return "operation_failed"
}

func CheckHTTP(parent context.Context, in Config) (int, error) {
	result, err := CheckHTTPDetailed(parent, in)
	return result.HTTPStatus, err
}

// CheckHTTPDetailed runs the same native-client check as CheckHTTP and retains
// authenticated connection state on a subsequent TLS or HTTP failure.
func CheckHTTPDetailed(parent context.Context, in Config) (result Result, returnedErr error) {
	result.Stage = "configuration"
	fail := func(class, message string) (Result, error) {
		result.ErrorClass = class
		return result, errors.New(message)
	}
	u, err := url.Parse(in.URL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return fail("invalid_configuration", "probe requires an HTTPS destination")
	}
	if parent == nil || len(in.Key) < 32 || len(in.Domain) < 3 || len(in.Resolvers) == 0 {
		return fail("invalid_configuration", "missing Cotten probe credentials or resolvers")
	}
	if in.Transport != "udp" && in.Transport != "tcp" && in.Transport != "auto" {
		return fail("invalid_configuration", "invalid Cotten DNS transport")
	}
	work, err := os.MkdirTemp("", "whitedns-cotten-check-")
	if err != nil {
		return fail("local_setup_failed", "Cotten probe temporary setup failed")
	}
	defer os.RemoveAll(work)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fail("local_setup_failed", "Cotten probe listener setup failed")
	}
	address := listener.Addr().String()
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	text := fmt.Sprintf(`PROTOCOL_TYPE = "SOCKS5"
LISTEN_IP = "127.0.0.1"
LISTEN_PORT = %d
SOCKS5_AUTH = false
DOMAINS = [%q]
ENCRYPTION_KEY = %q
DATA_ENCRYPTION_METHOD = 5
LEGACY_SESSION_ID = false
TERMINAL_UI = "plain"
STARTUP_MODE = "resolvers"
RESOLVER_TRANSPORT = %q
QUERY_TYPES = ["TXT"]
MIN_UPLOAD_MTU = 80
MAX_UPLOAD_MTU = 142
MIN_DOWNLOAD_MTU = 16
MAX_DOWNLOAD_MTU = 1500
MTU_TEST_RETRIES_RESOLVERS = 0
MTU_TEST_TIMEOUT_RESOLVERS = 2.0
MTU_TEST_PARALLELISM_RESOLVERS = 2
FAST_CONNECT = true
UPLOAD_PACKET_DUPLICATION_COUNT = 1
DOWNLOAD_PACKET_DUPLICATION_COUNT = 1
UPLOAD_SETUP_PACKET_DUPLICATION_COUNT = 1
DOWNLOAD_SETUP_PACKET_DUPLICATION_COUNT = 1
RECHECK_INACTIVE_SERVERS_ENABLED = false
AUTO_DISABLE_TIMEOUT_SERVERS = false
LOG_LEVEL = "ERROR"
LOG_DIR = %q
`, port, in.Domain, in.Key, in.Transport, work)
	configPath, resolverPath := filepath.Join(work, "client.toml"), filepath.Join(work, "resolvers.txt")
	if err = os.WriteFile(configPath, []byte(text), 0600); err != nil {
		return fail("local_setup_failed", "Cotten probe configuration could not be written")
	}
	if err = os.WriteFile(resolverPath, []byte(strings.Join(in.Resolvers, "\n")+"\n"), 0600); err != nil {
		return fail("local_setup_failed", "Cotten probe resolvers could not be written")
	}
	app, err := client.Bootstrap(configPath, config.ClientConfigOverrides{ResolversFilePath: &resolverPath})
	if err != nil {
		return fail("invalid_configuration", "Cotten probe configuration failed")
	}
	app.Log().SwapConsoleWriter(io.Discard)
	defer app.Log().Close()
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	var runtimeErr error
	go func() {
		defer close(done)
		runtimeErr = app.Run(ctx)
	}()
	state := &progress{stage: "startup"}
	defer func() {
		result.Stage, result.Handshake = state.snapshot()
		if result.OK {
			result.Stage = "complete"
		}
	}()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			if returnedErr == nil {
				result.OK, result.ErrorClass = false, "cleanup_timeout"
				state.mark("cleanup")
				returnedErr = errors.New("Cotten probe shutdown timed out")
			}
		}
	}()
	dialer, err := proxy.SOCKS5("tcp", address, nil, &net.Dialer{Timeout: 5 * time.Second})
	if err != nil {
		return fail("local_setup_failed", "Cotten probe proxy setup failed")
	}
	contextDialer := dialer.(proxy.ContextDialer)
	transport := &http.Transport{TLSClientConfig: in.TLSConfig, DisableKeepAlives: true, DialContext: func(ctx context.Context, network, target string) (net.Conn, error) {
		for {
			if app.StatusSnapshot().Phase == "connected" {
				state.connect()
				conn, err := contextDialer.DialContext(ctx, network, target)
				if err == nil {
					return conn, nil
				}
				var op *net.OpError
				if !errors.As(err, &op) || op.Op != "dial" {
					return nil, err
				}
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-done:
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				class := classifyError(runtimeErr)
				if class == "" {
					class = "client_stopped"
				}
				return nil, runtimeStoppedError{class: class}
			case <-time.After(50 * time.Millisecond):
			}
		}
	}}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	trace := &httptrace.ClientTrace{
		TLSHandshakeStart: func() { state.mark("tls") },
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			if err == nil {
				state.mark("http")
			}
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			if info.Err == nil {
				state.mark("http")
			}
		},
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), "GET", in.URL, nil)
	if err != nil {
		return fail("invalid_configuration", "Cotten probe request configuration failed")
	}
	response, err := httpClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		return fail(classifyError(err), "Cotten tunnel HTTPS test failed; check DNS transport and outbound access")
	}
	defer response.Body.Close()
	result.HTTPStatus = response.StatusCode
	state.mark("body")
	if _, err = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10)); err != nil {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		return fail(classifyError(err), "Cotten HTTPS response incomplete")
	}
	if response.StatusCode < 200 || response.StatusCode >= 400 {
		state.mark("http")
		return fail("http_status", "Cotten HTTPS destination returned an unsuccessful status")
	}
	result.OK = true
	return result, nil
}
