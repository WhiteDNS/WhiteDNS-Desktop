package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	cottenserver "cottendns-go/server"
)

const testKey = "test-only-probe-account-key-0000000001"

// Exercise the real encrypted client, framed TCP DNS transport, SOCKS proxy and
// embedded server. Only outbound origin dialing is redirected to a local test.
func testTunnel(t *testing.T, origin string) Config {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	engine, err := cottenserver.New(ctx, cottenserver.Config{
		Domain: "tunnel.example", Key: testKey,
		Allowed: func() bool { return true },
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", origin)
		},
		ExchangeDNS: func(context.Context, []byte) ([]byte, error) { return nil, errors.New("unused DNS egress") },
	})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		cancel()
		engine.Close()
		t.Fatal(err)
	}
	var mu sync.Mutex
	connections := make(map[net.Conn]struct{})
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			if ctx.Err() != nil {
				mu.Unlock()
				conn.Close()
				return
			}
			connections[conn] = struct{}{}
			mu.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer func() { conn.Close(); mu.Lock(); delete(connections, conn); mu.Unlock() }()
				for {
					var size [2]byte
					if _, err := io.ReadFull(conn, size[:]); err != nil {
						return
					}
					packet := make([]byte, int(binary.BigEndian.Uint16(size[:])))
					if _, err := io.ReadFull(conn, packet); err != nil {
						return
					}
					response := engine.HandleDNSTCP(packet)
					if len(response) == 0 {
						return
					}
					frame := binary.BigEndian.AppendUint16(nil, uint16(len(response)))
					if _, err := conn.Write(append(frame, response...)); err != nil {
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() {
		cancel()
		listener.Close()
		mu.Lock()
		for conn := range connections {
			conn.Close()
		}
		mu.Unlock()
		workers.Wait()
		engine.Close()
	})
	return Config{Domain: "tunnel.example", Key: testKey, Resolvers: []string{listener.Addr().String()}, Transport: "tcp", URL: "https://example.com/"}
}

func TestDetailedStartupTimeoutDoesNotClaimHandshake(t *testing.T) {
	work := t.TempDir()
	t.Setenv("TMPDIR", work)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	r, err := CheckHTTPDetailed(ctx, Config{Domain: "tunnel.example", Key: testKey, Resolvers: []string{listener.Addr().String()}, Transport: "tcp", URL: "https://example.com/"})
	if err == nil || r.OK || r.Handshake || r.Stage != "startup" || r.ErrorClass != "deadline_exceeded" {
		t.Fatalf("startup failure misreported: %+v, %v", r, err)
	}
	if strings.Contains(err.Error(), testKey) || strings.Contains(err.Error(), "tunnel.example") || strings.Contains(err.Error(), listener.Addr().String()) {
		t.Fatal("error exposed credentials or traffic metadata")
	}
	if entries, err := os.ReadDir(work); err != nil || len(entries) != 0 {
		t.Fatalf("private probe configuration was retained: %d entries, %v", len(entries), err)
	}
}

func TestDetailedSuccessfulHTTPS(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "complete test body") }))
	defer origin.Close()
	in := testTunnel(t, origin.Listener.Addr().String())
	roots := x509.NewCertPool()
	roots.AddCert(origin.Certificate())
	in.TLSConfig = &tls.Config{RootCAs: roots}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	r, err := CheckHTTPDetailed(ctx, in)
	if err != nil || !r.OK || !r.Handshake || r.Stage != "complete" || r.HTTPStatus != http.StatusOK || r.ErrorClass != "" {
		t.Fatalf("successful check misreported: %+v, %v", r, err)
	}
}

func TestDetailedTLSFailureRetainsAuthenticatedHandshake(t *testing.T) {
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") }))
	origin.Config.ErrorLog = log.New(io.Discard, "", 0)
	origin.StartTLS()
	defer origin.Close()
	in := testTunnel(t, origin.Listener.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	r, err := CheckHTTPDetailed(ctx, in)
	if err == nil || r.OK || !r.Handshake || r.Stage != "tls" || r.ErrorClass != "tls_certificate_error" {
		t.Fatalf("authenticated TLS failure misreported: %+v, %v", r, err)
	}
}

func TestDetailedHTTPTimeoutRetainsAuthenticatedHandshake(t *testing.T) {
	started := make(chan struct{})
	origin := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}))
	defer origin.Close()
	in := testTunnel(t, origin.Listener.Addr().String())
	roots := x509.NewCertPool()
	roots.AddCert(origin.Certificate())
	in.TLSConfig = &tls.Config{RootCAs: roots}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r, err := CheckHTTPDetailed(ctx, in)
	select {
	case <-started:
	default:
		t.Fatal("request never reached delayed HTTP origin")
	}
	if err == nil || r.OK || !r.Handshake || r.Stage != "http" || r.ErrorClass != "deadline_exceeded" {
		t.Fatalf("authenticated HTTP timeout misreported: %+v, %v", r, err)
	}
}

func TestCheckHTTPCompatibilityWrapper(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer origin.Close()
	in := testTunnel(t, origin.Listener.Addr().String())
	roots := x509.NewCertPool()
	roots.AddCert(origin.Certificate())
	in.TLSConfig = &tls.Config{RootCAs: roots}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	status, err := CheckHTTP(ctx, in)
	if status != http.StatusServiceUnavailable || err == nil {
		t.Fatalf("compatibility wrapper lost HTTP status: %d, %v", status, err)
	}
}
