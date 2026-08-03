// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// server_encrypted_test.go — locks the DoH request parser and the shared TLS
// material builder. The DoT listener is intentionally not re-tested end to end:
// it reuses serveDNSOverStream, already covered by the TCP tests, with only a
// tls.NewListener wrap added.
// ==============================================================================

package udpserver

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func wireQuery(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func TestDecodeDoHQuery(t *testing.T) {
	valid := wireQuery(24)

	cases := []struct {
		name       string
		req        *http.Request
		wantStatus int
		wantBody   []byte
	}{
		{
			name:       "post wire format",
			req:        httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(valid)),
			wantStatus: http.StatusOK,
			wantBody:   valid,
		},
		{
			name: "post correct content type",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(valid))
				r.Header.Set("Content-Type", dohContentType)
				return r
			}(),
			wantStatus: http.StatusOK,
			wantBody:   valid,
		},
		{
			name: "post wrong content type rejected",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(valid))
				r.Header.Set("Content-Type", "application/json")
				return r
			}(),
			wantStatus: http.StatusUnsupportedMediaType,
		},
		{
			name:       "get base64url",
			req:        httptest.NewRequest(http.MethodGet, "/dns-query?dns="+base64.RawURLEncoding.EncodeToString(valid), nil),
			wantStatus: http.StatusOK,
			wantBody:   valid,
		},
		{
			// 22 bytes is not a multiple of 3, so StdEncoding appends '=' padding
			// that RawURLEncoding must reject — proving we require unpadded base64url.
			name:       "get padded base64 rejected",
			req:        httptest.NewRequest(http.MethodGet, "/dns-query?dns="+base64.StdEncoding.EncodeToString(wireQuery(22)), nil),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "too short rejected",
			req:        httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(wireQuery(4))),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "oversized rejected",
			req:        httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(wireQuery(dohMaxMessageSize+1))),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "method not allowed",
			req:        httptest.NewRequest(http.MethodPut, "/dns-query", bytes.NewReader(valid)),
			wantStatus: http.StatusMethodNotAllowed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, status := decodeDoHQuery(tc.req)
			if status != tc.wantStatus {
				t.Fatalf("status = %d, want %d", status, tc.wantStatus)
			}
			if tc.wantStatus == http.StatusOK && !bytes.Equal(got, tc.wantBody) {
				t.Fatalf("query mismatch: got %d bytes, want %d", len(got), len(tc.wantBody))
			}
		})
	}
}

func TestAcmeEligibleDomainsFiltersNonIssuable(t *testing.T) {
	got := acmeEligibleDomains([]string{
		"tunnel.example.com.",
		"1.2.3.4",          // IP literal — not issuable
		"*.wild.example",   // wildcard — needs DNS-01
		"localhost",        // no dot — not a public name
		"  edge.example  ", // trims to a valid name
		"",                 // empty
	})
	want := []string{"tunnel.example.com", "edge.example"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestGenerateSelfSignedCertCoversDomainsAndIPs(t *testing.T) {
	cert, err := generateSelfSignedCert([]string{"tunnel.example.com", "203.0.113.7"})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if cert.Leaf == nil {
		t.Fatal("expected a parsed leaf certificate")
	}
	if len(cert.Leaf.DNSNames) != 1 || cert.Leaf.DNSNames[0] != "tunnel.example.com" {
		t.Fatalf("DNS SANs = %v", cert.Leaf.DNSNames)
	}
	if len(cert.Leaf.IPAddresses) != 1 || cert.Leaf.IPAddresses[0].String() != "203.0.113.7" {
		t.Fatalf("IP SANs = %v", cert.Leaf.IPAddresses)
	}
}

func TestTLSConfigALPNsSeparateDoTAndDoH(t *testing.T) {
	base := &tls.Config{NextProtos: []string{"acme-tls/1"}}
	dot := dotTLSConfig(base)
	doh := dohTLSConfig(base)

	if got := strings.Join(dot.NextProtos, ","); got != "dot,acme-tls/1" {
		t.Fatalf("dot ALPNs = %q, want %q", got, "dot,acme-tls/1")
	}
	if got := strings.Join(doh.NextProtos, ","); got != "h2,http/1.1,acme-tls/1" {
		t.Fatalf("doh ALPNs = %q, want %q", got, "h2,http/1.1,acme-tls/1")
	}
}

func TestDoHRequestClientIPHonorsTrustedProxyHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/dns-query", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.1")
	trusted := newTrustedProxySet([]string{"127.0.0.1"})
	if got := dohRequestClientIP(req, trusted); got != "203.0.113.9" {
		t.Fatalf("client IP = %q, want 203.0.113.9", got)
	}
}
