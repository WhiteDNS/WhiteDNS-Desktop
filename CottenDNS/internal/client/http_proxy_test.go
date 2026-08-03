// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
package client

import (
	"bufio"
	"bytes"
	"net"
	"net/http"
	"strings"
	"testing"
)

// TestHTTPProxy_ParseCONNECT verifies CONNECT request parsing extracts the
// correct host and port.
func TestHTTPProxy_ParseCONNECT(t *testing.T) {
	raw := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}
	if req.Method != "CONNECT" {
		t.Fatalf("expected CONNECT, got %s", req.Method)
	}
	host, port, err := net.SplitHostPort(req.Host)
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	if host != "example.com" || port != "443" {
		t.Fatalf("unexpected host/port: %s:%s", host, port)
	}
}

// TestHTTPProxy_ParsePlain verifies that a plain HTTP proxy request is
// rewritten to a relative URI and that proxy-specific headers are stripped.
func TestHTTPProxy_ParsePlain(t *testing.T) {
	raw := "GET http://example.com/path?q=1 HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\n\r\n"
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}

	req.RequestURI = req.URL.RequestURI()
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authorization")

	var buf bytes.Buffer
	if err := req.Write(&buf); err != nil {
		t.Fatalf("req.Write: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "http://example.com") {
		t.Fatalf("absolute URI not rewritten: %s", out)
	}
	if strings.Contains(out, "Proxy-Connection") {
		t.Fatalf("Proxy-Connection header not stripped: %s", out)
	}
	if !strings.Contains(out, "GET /path?q=1") {
		t.Fatalf("relative path missing: %s", out)
	}
}

// TestHTTPProxy_VersionConstants ensures the HTTP proxy sentinel bytes don't
// collide with SOCKS4/SOCKS5 version bytes.
func TestHTTPProxy_VersionConstants(t *testing.T) {
	if httpProxyCONNECT == SOCKS4_VERSION || httpProxyCONNECT == SOCKS5_VERSION {
		t.Fatalf("httpProxyCONNECT collides with SOCKS version byte")
	}
	if httpProxyPlain == SOCKS4_VERSION || httpProxyPlain == SOCKS5_VERSION {
		t.Fatalf("httpProxyPlain collides with SOCKS version byte")
	}
	if httpProxyCONNECT == httpProxyPlain {
		t.Fatalf("httpProxyCONNECT == httpProxyPlain")
	}
}
