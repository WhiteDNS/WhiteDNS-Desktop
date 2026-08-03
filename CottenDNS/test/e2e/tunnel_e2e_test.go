//go:build e2e

// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// tunnel_e2e_test.go — end-to-end smoke test for the full DNS tunnel: it builds
// the real client and server binaries, runs them against each other over UDP
// loopback (server in TCP-forward mode pointed at an in-test echo server), then
// pushes a payload through the client's TCP listener and asserts it round-trips
// byte-for-byte.
//
// This is the safety net for wire-format / protocol changes. It is gated behind
// the `e2e` build tag so it never runs in the default `go test ./...`:
//
//	go test -tags e2e -timeout 120s ./test/e2e/
//
// The config blocks below are lifted from scripts/bench/bench.go, which is a
// known-good runtime configuration for the current client/server.
// ==============================================================================

package e2e

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// repoRoot returns the module root (two levels up from this test file's dir).
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd() // .../test/e2e
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

func binName(base string) string {
	if runtime.GOOS == "windows" {
		return base + ".exe"
	}
	return base
}

func buildBinary(t *testing.T, root, pkg, outPath string) {
	t.Helper()
	cmd := exec.Command("go", "build", "-o", outPath, pkg)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build %s failed: %v\n%s", pkg, err, out)
	}
}

// freeUDPPort grabs an ephemeral UDP port and releases it for the server to bind.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve udp: %v", err)
	}
	c, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	port := c.LocalAddr().(*net.UDPAddr).Port
	_ = c.Close()
	return port
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

type safeBuf struct {
	sync.Mutex
	buf bytes.Buffer
}

func (b *safeBuf) Write(p []byte) (int, error) {
	b.Lock()
	defer b.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuf) String() string {
	b.Lock()
	defer b.Unlock()
	return b.buf.String()
}

func waitForFile(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if info, err := os.Stat(path); err == nil && info.Size() > 0 {
			return nil
		}
		time.Sleep(150 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for file: %s", path)
}

func waitForPattern(buf *safeBuf, pattern string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(buf.String(), pattern) {
			return nil
		}
		time.Sleep(150 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for pattern %q", pattern)
}

// startEchoServer starts a TCP echo server that the CottenDns server (in TCP
// mode) forwards tunneled connections to. Returns its port.
func startEchoServer(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestTunnelEndToEndEcho(t *testing.T) {
	// Matched encryption method on both sides (baseline + A1/A2/A6 coverage).
	runTunnelEcho(t, 1, 1, "", "", "")
}

func TestTunnelEndToEndEncryptionAutoDetect(t *testing.T) {
	// Server configured for method 1 (XOR); client uses method 3 (AES-128-GCM)
	// with the same shared key. The tunnel must still come up, proving the
	// server auto-detects the client's encryption method.
	runTunnelEcho(t, 1, 3, "", "", "")
}

func TestTunnelEndToEndFECDownload(t *testing.T) {
	// Server delivers all download data over PACKET_FEC_SHARD instead of raw
	// STREAM_DATA. The payload must still round-trip byte-for-byte, proving the
	// server's FEC encode path and the client's decode/replay path are wired
	// correctly end-to-end through the real wire framing.
	runTunnelEcho(t, 1, 1, "FEC_DOWNLOAD_ENABLED = true\nFEC_BLOCK_SIZE = 4\nFEC_PARITY = 4\n", "", "")
}

func TestTunnelEndToEndNewTransportChannels(t *testing.T) {
	// Client rotates over the new NULL and HTTPS response channels (plus TXT and
	// CNAME). The server must auto-accept every query type and answer with the
	// matching RR type, with no server-side channel configuration. A byte-exact
	// echo proves the new channels are wired end-to-end and default-accepted.
	runTunnelEcho(t, 1, 1, "", `["TXT", "CNAME", "NULL", "HTTPS"]`, "")
}

func TestTunnelEndToEndTCPTransport(t *testing.T) {
	// Force the client onto DNS-over-TCP/53. The server's TCP listener (default
	// on) must serve the entire tunnel — probe, session init, and data plane —
	// and echo 64 KB byte-for-byte, proving the TCP fallback works end to end.
	runTunnelEcho(t, 1, 1, "", "", "RESOLVER_TRANSPORT = \"tcp\"\n")
}

func TestTunnelEndToEndTCPWithNonTXTChannels(t *testing.T) {
	// Integration check: DNS-over-TCP/53 transport AND the non-TXT response
	// channels (NULL, HTTPS) together. The client rotates query types over TCP;
	// the server must answer each with the matching record type over TCP framing
	// and the payload must still round-trip byte-for-byte.
	runTunnelEcho(t, 1, 1, "", `["TXT", "CNAME", "NULL", "HTTPS"]`, "RESOLVER_TRANSPORT = \"tcp\"\n")
}

func TestTunnelEndToEndReshapedQNameTCPNonTXT(t *testing.T) {
	// Strongest integration: reshaped QNAME (short, jittered labels) + DNS-over-
	// TCP/53 + the non-TXT CNAME/NULL/HTTPS response channels, all at once. Proves
	// the query-name reshaping composes with the TCP fallback and every response
	// channel, with a byte-exact 64 KB echo.
	runTunnelEcho(t, 1, 1, "", `["TXT", "CNAME", "NULL", "HTTPS"]`,
		"RESOLVER_TRANSPORT = \"tcp\"\nQNAME_LABEL_LENGTH = 24\n")
}

func runTunnelEcho(t *testing.T, serverMethod, clientMethod int, serverExtra, clientQueryTypes, clientExtra string) {
	if clientQueryTypes == "" {
		clientQueryTypes = `["TXT", "CNAME", "A", "AAAA"]`
	}
	root := repoRoot(t)
	work := t.TempDir()

	serverBin := filepath.Join(work, binName("server"))
	clientBin := filepath.Join(work, binName("client"))
	buildBinary(t, root, "./cmd/server", serverBin)
	buildBinary(t, root, "./cmd/client", clientBin)

	echoPort := startEchoServer(t)
	udpPort := freeUDPPort(t)
	clientPort := freeTCPPort(t)

	serverCfg := filepath.Join(work, "server_config.toml")
	clientCfg := filepath.Join(work, "client_config.toml")
	keyFile := filepath.Join(work, "encrypt_key.txt")

	// Server: TCP mode, forwards every tunneled connection to the echo server.
	if err := os.WriteFile(serverCfg, []byte(fmt.Sprintf(`
PROTOCOL_TYPE = "TCP"
UDP_HOST = "127.0.0.1"
UDP_PORT = %d
DOMAIN = ["a.io"]
MIN_VPN_LABEL_LENGTH = 1
DATA_ENCRYPTION_METHOD = %d
ENCRYPTION_KEY_FILE = "encrypt_key.txt"
FORWARD_IP = "127.0.0.1"
FORWARD_PORT = %d
MAX_PACKETS_PER_BATCH = 5
ARQ_WINDOW_SIZE = 16384
ARQ_INITIAL_RTO_SECONDS = 0.25
ARQ_MAX_RTO_SECONDS = 1.0
UDP_READERS = 8
DNS_REQUEST_WORKERS = 8
DEFERRED_SESSION_WORKERS = 4
MAX_CONCURRENT_REQUESTS = 16384
LOG_LEVEL = "INFO"
SUPPORTED_UPLOAD_COMPRESSION_TYPES = [0, 1, 2, 3]
SUPPORTED_DOWNLOAD_COMPRESSION_TYPES = [0, 1, 2, 3]
SOCKET_BUFFER_SIZE = 8388608
MAX_PACKET_SIZE = 65535
DEFERRED_SESSION_QUEUE_LIMIT = 4096
SESSION_ORPHAN_QUEUE_INITIAL_CAPACITY = 128
STREAM_QUEUE_INITIAL_CAPACITY = 256
DNS_FRAGMENT_STORE_CAPACITY = 512
SOCKS5_FRAGMENT_STORE_CAPACITY = 1024
PACKET_BLOCK_CONTROL_DUPLICATION = 1
STREAM_SETUP_ACK_TTL_SECONDS = 400.0
STREAM_RESULT_PACKET_TTL_SECONDS = 300.0
STREAM_FAILURE_PACKET_TTL_SECONDS = 120.0
ARQ_CONTROL_INITIAL_RTO_SECONDS = 0.25
ARQ_CONTROL_MAX_RTO_SECONDS = 1.0
ARQ_MAX_CONTROL_RETRIES = 300
ARQ_INACTIVITY_TIMEOUT_SECONDS = 1800.0
ARQ_DATA_PACKET_TTL_SECONDS = 2400.0
ARQ_CONTROL_PACKET_TTL_SECONDS = 1200.0
ARQ_MAX_DATA_RETRIES = 1200
ARQ_DATA_NACK_MAX_GAP = 128
ARQ_DATA_NACK_INITIAL_DELAY_SECONDS = 0.35
ARQ_DATA_NACK_REPEAT_SECONDS = 0.8
ARQ_TERMINAL_DRAIN_TIMEOUT_SECONDS = 120.0
ARQ_TERMINAL_ACK_WAIT_TIMEOUT_SECONDS = 90.0
%s
`, udpPort, serverMethod, echoPort, serverExtra)), 0644); err != nil {
		t.Fatalf("write server cfg: %v", err)
	}

	serverLog := &safeBuf{}
	serverCmd := exec.Command(serverBin, "--config", serverCfg)
	serverCmd.Dir = work
	serverCmd.Stdout = serverLog
	serverCmd.Stderr = serverLog
	if err := serverCmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	t.Cleanup(func() { _ = serverCmd.Process.Kill() })

	if err := waitForFile(keyFile, 20*time.Second); err != nil {
		t.Fatalf("server did not generate key file: %v\n--- server log ---\n%s", err, serverLog.String())
	}
	keyData, _ := os.ReadFile(keyFile)
	encryptionKey := strings.TrimSpace(string(keyData))

	resolverFile := filepath.Join(work, "client_resolvers.txt")
	if err := os.WriteFile(resolverFile, []byte(fmt.Sprintf("127.0.0.1:%d\n", udpPort)), 0644); err != nil {
		t.Fatalf("write resolvers: %v", err)
	}

	if err := os.WriteFile(clientCfg, []byte(fmt.Sprintf(`
PROTOCOL_TYPE = "TCP"
LISTEN_IP = "127.0.0.1"
LISTEN_PORT = %d
DOMAINS = ["a.io"]
ENCRYPTION_KEY = "%s"
QUERY_TYPES = %s
RESOLVER_BALANCING_STRATEGY = 1
DATA_ENCRYPTION_METHOD = %d
UPLOAD_PACKET_DUPLICATION_COUNT = 1
DOWNLOAD_PACKET_DUPLICATION_COUNT = 1
UPLOAD_SETUP_PACKET_DUPLICATION_COUNT = 1
DOWNLOAD_SETUP_PACKET_DUPLICATION_COUNT = 1
MIN_UPLOAD_MTU = 80
MIN_DOWNLOAD_MTU = 4000
MAX_UPLOAD_MTU = 142
MAX_DOWNLOAD_MTU = 4000
MTU_TEST_RETRIES_RESOLVERS = 0
MTU_TEST_TIMEOUT_RESOLVERS = 1.0
MTU_TEST_PARALLELISM_RESOLVERS = 1
MTU_TEST_RETRIES_LOGS = 0
MTU_TEST_TIMEOUT_LOGS = 1.0
MTU_TEST_PARALLELISM_LOGS = 1
TUNNEL_READER_WORKERS = 20
TUNNEL_WRITER_WORKERS = 20
TUNNEL_PROCESS_WORKERS = 20
TX_CHANNEL_SIZE = 32768
RX_CHANNEL_SIZE = 32768
ARQ_WINDOW_SIZE = 16384
ARQ_INITIAL_RTO_SECONDS = 0.25
ARQ_MAX_RTO_SECONDS = 1.0
DISPATCHER_IDLE_POLL_INTERVAL_SECONDS = 0.002
LOG_LEVEL = "INFO"
PING_AGGRESSIVE_INTERVAL_SECONDS = 0.030
PING_LAZY_INTERVAL_SECONDS = 0.100
PING_COOLDOWN_INTERVAL_SECONDS = 1.0
PING_COLD_INTERVAL_SECONDS = 10.0
PING_WARM_THRESHOLD_SECONDS = 10.0
PING_COOL_THRESHOLD_SECONDS = 15.0
PING_COLD_THRESHOLD_SECONDS = 30.0
ARQ_CONTROL_INITIAL_RTO_SECONDS = 0.25
ARQ_CONTROL_MAX_RTO_SECONDS = 1.0
ARQ_INACTIVITY_TIMEOUT_SECONDS = 1800.0
ARQ_DATA_PACKET_TTL_SECONDS = 2400.0
ARQ_CONTROL_PACKET_TTL_SECONDS = 1200.0
ARQ_MAX_DATA_RETRIES = 1200
ARQ_DATA_NACK_MAX_GAP = 128
STREAM_RESOLVER_FAILOVER_RESEND_THRESHOLD = 50
STREAM_RESOLVER_FAILOVER_COOLDOWN = 10.0
RECHECK_INACTIVE_SERVERS_ENABLED = false
AUTO_DISABLE_TIMEOUT_SERVERS = false
UPLOAD_COMPRESSION_TYPE = 0
DOWNLOAD_COMPRESSION_TYPE = 0
COMPRESSION_MIN_SIZE = 120
TUNNEL_PACKET_TIMEOUT_SECONDS = 10.0
RESOLVER_UDP_CONNECTION_POOL_SIZE = 512
STREAM_QUEUE_INITIAL_CAPACITY = 512
ORPHAN_QUEUE_INITIAL_CAPACITY = 256
MAX_PACKETS_PER_BATCH = 1
ARQ_MAX_CONTROL_RETRIES = 300
ARQ_DATA_NACK_INITIAL_DELAY_SECONDS = 0.35
ARQ_DATA_NACK_REPEAT_SECONDS = 0.8
%s
`, clientPort, encryptionKey, clientQueryTypes, clientMethod, clientExtra)), 0644); err != nil {
		t.Fatalf("write client cfg: %v", err)
	}

	clientLog := &safeBuf{}
	clientCmd := exec.Command(clientBin, "--config", clientCfg)
	clientCmd.Dir = work
	clientCmd.Stdout = clientLog
	clientCmd.Stderr = clientLog
	if err := clientCmd.Start(); err != nil {
		t.Fatalf("start client: %v", err)
	}
	t.Cleanup(func() { _ = clientCmd.Process.Kill() })

	if err := waitForPattern(clientLog, "is listening", 40*time.Second); err != nil {
		t.Fatalf("client did not start listening: %v\n--- client log ---\n%s\n--- server log ---\n%s",
			err, clientLog.String(), serverLog.String())
	}

	// Push a payload through the tunnel and assert it echoes back intact.
	const payloadSize = 64 * 1024
	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte('A' + (i % 26))
	}

	var conn net.Conn
	var dialErr error
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		conn, dialErr = net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", clientPort), 3*time.Second)
		if dialErr == nil {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if dialErr != nil {
		t.Fatalf("dial client listener: %v\n--- client log ---\n%s", dialErr, clientLog.String())
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))

	writeErr := make(chan error, 1)
	go func() {
		_, err := conn.Write(payload)
		writeErr <- err
	}()

	got := make([]byte, 0, payloadSize)
	buf := make([]byte, 16*1024)
	for len(got) < payloadSize {
		n, err := conn.Read(buf)
		if n > 0 {
			got = append(got, buf[:n]...)
		}
		if err != nil {
			t.Fatalf("read echo (%d/%d bytes): %v\n--- client log ---\n%s\n--- server log ---\n%s",
				len(got), payloadSize, err, clientLog.String(), serverLog.String())
		}
	}

	if err := <-writeErr; err != nil {
		t.Fatalf("write payload: %v", err)
	}

	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: got %d bytes, want %d, equal-prefix=%d",
			len(got), payloadSize, commonPrefix(got, payload))
	}
}

func commonPrefix(a, b []byte) int {
	n := 0
	for n < len(a) && n < len(b) && a[n] == b[n] {
		n++
	}
	return n
}
