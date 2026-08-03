// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// tls_client.go — TLS material for the encrypted resolver transports (DoT/DoH).
//
// Trust model, in order of preference:
//   1. RESOLVER_TLS_PIN set        — pin the server's SubjectPublicKeyInfo hash.
//      Verification is done by us, not the system roots, so a self-signed or
//      private-CA server is trusted exactly and nothing else is.
//   2. default                     — normal hostname/CA verification against
//      RESOLVER_TLS_SERVER_NAME (or the resolver IP when unset).
//   3. RESOLVER_TLS_INSECURE_SKIP_VERIFY — last resort, off by default.
//
// Worth being explicit about what this layer is and is not for: the tunnel
// payload is already AEAD-encrypted end to end, so TLS here buys traffic
// *disguise* (looking like ordinary encrypted DNS to DPI), not payload secrecy.
// That is why even mode 3 never exposes tunnel data — but pinning is still
// preferred, because an unverified hop can be transparently intercepted and the
// interception itself is a censorship signal.
// ==============================================================================

package client

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

var errResolverPinMismatch = errors.New("resolver TLS certificate does not match RESOLVER_TLS_PIN")

// resolverTLSConfig builds the shared *tls.Config used by the DoT and DoH
// transports. serverName may be overridden per-connection by the caller when the
// configured name is empty (so SNI falls back to the resolver address).
func (c *Client) resolverTLSConfig() *tls.Config {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: strings.TrimSpace(c.cfg.ResolverTLSServerName),
	}

	if pin := strings.TrimSpace(c.cfg.ResolverTLSPin); pin != "" {
		// Pinning replaces chain validation: verify the presented key ourselves so
		// a self-signed resolver is trusted exactly, and only it.
		cfg.InsecureSkipVerify = true
		cfg.VerifyPeerCertificate = pinnedSPKIVerifier(pin)
		return cfg
	}

	cfg.InsecureSkipVerify = c.cfg.ResolverTLSInsecureSkipVerify
	return cfg
}

// pinnedSPKIVerifier returns a VerifyPeerCertificate that accepts only a leaf
// certificate whose SubjectPublicKeyInfo SHA-256 matches pin (base64). Pinning
// the SPKI rather than the whole certificate means the server can renew/reissue
// without breaking clients, as long as it keeps its key.
func pinnedSPKIVerifier(pin string) func([][]byte, [][]*x509.Certificate) error {
	want := normalizePin(pin)
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errResolverPinMismatch
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("parse resolver certificate: %w", err)
		}
		sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
		if normalizePin(base64.StdEncoding.EncodeToString(sum[:])) != want {
			return errResolverPinMismatch
		}
		return nil
	}
}

// normalizePin tolerates the common ways a pin gets pasted: with or without a
// "sha256/" prefix, base64 padding, or surrounding whitespace.
func normalizePin(pin string) string {
	pin = strings.TrimSpace(pin)
	pin = strings.TrimPrefix(pin, "sha256/")
	pin = strings.TrimPrefix(pin, "sha256:")
	return strings.TrimRight(strings.TrimSpace(pin), "=")
}
