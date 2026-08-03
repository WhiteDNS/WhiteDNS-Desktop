// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// server_sni_router_test.go — the SNI peek is on the shared :443 path, so a
// parsing bug could break the co-hosted service. These tests pin that it reads
// the SNI from a real ClientHello, replays every consumed byte for the next
// handler, and never panics on malformed input.
// ==============================================================================

package udpserver

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

// writeRealClientHello dials TLS against a throwaway pipe just far enough to emit
// a genuine ClientHello with the given SNI, and returns those raw bytes.
func realClientHelloBytes(t *testing.T, serverName string) []byte {
	t.Helper()
	client, server := net.Pipe()
	captured := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 4096)
		_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ := server.Read(buf)
		captured <- append([]byte(nil), buf[:n]...)
		_ = server.Close()
	}()
	tlsConn := tls.Client(client, &tls.Config{ServerName: serverName, InsecureSkipVerify: true})
	_ = tlsConn.SetDeadline(time.Now().Add(2 * time.Second))
	_ = tlsConn.Handshake() // will fail (pipe peer never replies) — we only want the ClientHello
	_ = tlsConn.Close()
	select {
	case b := <-captured:
		return b
	case <-time.After(2 * time.Second):
		t.Fatal("timed out capturing ClientHello")
		return nil
	}
}

func TestPeekClientHelloSNIExtractsAndReplays(t *testing.T) {
	hello := realClientHelloBytes(t, "tunnel.example.com")

	a, b := net.Pipe()
	go func() {
		_, _ = a.Write(hello)
		// Emit one extra byte after the ClientHello to prove replay + live reads
		// stitch together seamlessly.
		_, _ = a.Write([]byte{0xEE})
		_ = a.Close()
	}()

	sni, buffered, err := peekClientHelloSNI(b)
	if err != nil {
		t.Fatalf("peek error: %v", err)
	}
	if sni != "tunnel.example.com" {
		t.Fatalf("sni = %q, want tunnel.example.com", sni)
	}
	if !bytes.Equal(buffered, hello) {
		t.Fatalf("buffered bytes (%d) do not match the consumed ClientHello (%d)", len(buffered), len(hello))
	}

	// Replaying the buffer then reading the tail must reproduce hello + 0xEE.
	replay := &prefixConn{Conn: b, prefix: buffered}
	got, _ := io.ReadAll(replay)
	want := append(append([]byte(nil), hello...), 0xEE)
	if !bytes.Equal(got, want) {
		t.Fatalf("replay produced %d bytes, want %d", len(got), len(want))
	}
}

func TestParseClientHelloSNIRejectsMalformed(t *testing.T) {
	hello := realClientHelloBytes(t, "x.example")
	body := hello[tlsRecordHdrLen:] // strip the record header

	// Every truncation of a valid ClientHello must return an error, never panic.
	for cut := 0; cut < len(body); cut++ {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on truncated hello at %d: %v", cut, r)
				}
			}()
			_, _ = parseClientHelloSNI(body[:cut])
		}()
	}

	// Random junk and empty input are errors, not panics.
	for _, junk := range [][]byte{nil, {0x01}, {0x01, 0x00, 0x00, 0xff}, bytes.Repeat([]byte{0xAB}, 200)} {
		if _, err := parseClientHelloSNI(junk); err == nil {
			t.Fatalf("expected error for junk %v", junk)
		}
	}
}

func TestTLSSNIMatcherExactOnly(t *testing.T) {
	m := tlsSNIMatcher([]string{"tunnel.example.com.", "Edge.Example"})
	if !m("tunnel.example.com") || !m("edge.example") || !m("EDGE.EXAMPLE") {
		t.Fatal("exact (case-insensitive) matches should pass")
	}
	if m("evil.com") || m("sub.tunnel.example.com") || m("") {
		t.Fatal("non-domain / subdomain / empty must not match (they belong to the co-hosted service)")
	}
}
