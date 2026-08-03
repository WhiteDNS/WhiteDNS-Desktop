// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// transport_chain_test.go — locks the resolver transport contract:
//
//   - DoT/DoH are opt-in only: nothing ever escalates into them.
//   - Choosing one is not a commitment: both fall back to UDP then TCP/53, so a
//     blocked TLS port degrades to the survival path instead of no tunnel.
//   - Certificate pinning accepts exactly the pinned key and nothing else.
// ==============================================================================

package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"cottendns-go/internal/config"
)

func transportNames(chain []resolverTransport) []string {
	out := make([]string, 0, len(chain))
	for _, t := range chain {
		out = append(out, t.String())
	}
	return out
}

func TestResolverTransportChainFallbacks(t *testing.T) {
	cases := []struct {
		name string
		want []string
	}{
		{"udp", []string{"UDP/53"}},
		{"tcp", []string{"TCP/53"}},
		{"auto", []string{"UDP/53", "TCP/53"}},
		{"dot", []string{"DoT", "UDP/53", "TCP/53"}},
		{"doh", []string{"DoH", "UDP/53", "TCP/53"}},
		{"DoH", []string{"DoH", "UDP/53", "TCP/53"}}, // case-insensitive
	}
	for _, tc := range cases {
		got := transportNames(resolverTransportChain(tc.name))
		if len(got) != len(tc.want) {
			t.Fatalf("%s: chain %v, want %v", tc.name, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("%s: chain %v, want %v", tc.name, got, tc.want)
			}
		}
	}
}

// The plain transports must never escalate into the encrypted ones: DoT/DoH are
// a disguise the operator opts into, not a rescue path.
func TestPlainTransportsNeverEscalateToEncrypted(t *testing.T) {
	for _, name := range []string{"udp", "tcp", "auto"} {
		for _, transport := range resolverTransportChain(name) {
			if transport == transportDoT || transport == transportDoH {
				t.Fatalf("%q must not fall back into %s", name, transport)
			}
		}
	}
}

// Every chain must end on a plain survival transport, so a blocked TLS port can
// always degrade to something that still carries the tunnel.
func TestEncryptedChainsEndOnSurvivalTransport(t *testing.T) {
	for _, name := range []string{"dot", "doh"} {
		chain := resolverTransportChain(name)
		last := chain[len(chain)-1]
		if last != transportTCP && last != transportUDP {
			t.Fatalf("%q chain ends on %s, expected a plain transport", name, last)
		}
	}
}

func TestUsesStreamTransportOnlyForNonUDP(t *testing.T) {
	c := &Client{}
	for transport, wantStream := range map[resolverTransport]bool{
		transportUDP: false,
		transportTCP: true,
		transportDoT: true,
		transportDoH: true,
	} {
		c.setActiveTransport(transport)
		if got := c.usesStreamTransport(); got != wantStream {
			t.Fatalf("%s: usesStreamTransport=%v, want %v", transport, got, wantStream)
		}
	}
}

func TestResolverHostWithPortReplacesResolverPort(t *testing.T) {
	cases := map[string]string{
		"1.1.1.1:53":  "1.1.1.1:853",
		"1.1.1.1":     "1.1.1.1:853",
		"[2001:db8::1]:53": "[2001:db8::1]:853",
	}
	for in, want := range cases {
		if got := resolverHostWithPort(in, 853); got != want {
			t.Fatalf("resolverHostWithPort(%q) = %q, want %q", in, got, want)
		}
	}
}

// A pin must accept the exact key it names and reject every other certificate,
// which is what makes trusting a self-signed resolver safe.
func TestPinnedSPKIVerifier(t *testing.T) {
	mine, err := generateTestCert()
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	other, err := generateTestCert()
	if err != nil {
		t.Fatalf("cert: %v", err)
	}

	leaf, err := x509.ParseCertificate(mine.Certificate[0])
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	pin := base64.StdEncoding.EncodeToString(sum[:])

	verify := pinnedSPKIVerifier(pin)
	if err := verify([][]byte{mine.Certificate[0]}, nil); err != nil {
		t.Fatalf("pinned certificate rejected: %v", err)
	}
	if err := verify([][]byte{other.Certificate[0]}, nil); err == nil {
		t.Fatal("a different certificate must not satisfy the pin")
	}
	if err := verify(nil, nil); err == nil {
		t.Fatal("an empty chain must not satisfy the pin")
	}

	// The common paste variations must resolve to the same pin.
	for _, variant := range []string{"sha256/" + pin, "sha256:" + pin, "  " + pin + "  "} {
		if err := pinnedSPKIVerifier(variant)([][]byte{mine.Certificate[0]}, nil); err != nil {
			t.Fatalf("pin variant %q rejected: %v", variant, err)
		}
	}
}

// Pinning must not also demand system-CA validation, otherwise a self-signed
// resolver could never be trusted; skip-verify must stay off unless asked for.
func TestResolverTLSConfigTrustModes(t *testing.T) {
	pinned := &Client{cfg: config.ClientConfig{ResolverTLSPin: "abc", ResolverTLSServerName: "dns.example"}}
	cfg := pinned.resolverTLSConfig()
	if !cfg.InsecureSkipVerify || cfg.VerifyPeerCertificate == nil {
		t.Fatal("pinned mode must replace chain validation with the pin verifier")
	}
	if cfg.ServerName != "dns.example" {
		t.Fatalf("ServerName = %q", cfg.ServerName)
	}

	def := (&Client{cfg: config.ClientConfig{}}).resolverTLSConfig()
	if def.InsecureSkipVerify || def.VerifyPeerCertificate != nil {
		t.Fatal("default mode must use normal verification")
	}

	skip := (&Client{cfg: config.ClientConfig{ResolverTLSInsecureSkipVerify: true}}).resolverTLSConfig()
	if !skip.InsecureSkipVerify {
		t.Fatal("explicit skip-verify was not honoured")
	}
}

// generateTestCert mints a throwaway self-signed certificate; each call uses a
// fresh key so two calls never share a SubjectPublicKeyInfo.
func generateTestCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pin-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
