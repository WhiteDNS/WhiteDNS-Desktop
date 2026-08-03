// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// server_tls.go — TLS material shared by the DoT and DoH listeners. Resolution
// order matches the operator's intent (and is only run when DoT/DoH is enabled):
//
//  1. TLS_CERT_FILE + TLS_KEY_FILE      — a real cert; the best DPI disguise.
//  2. ACME / Let's Encrypt for DOMAIN   — auto-obtained + renewed, needs :443.
//  3. self-signed generated at startup  — so the server always boots.
//
// The tunnel payload is already AEAD-encrypted end to end, so this TLS layer is
// about making the traffic look like ordinary encrypted DNS, not about payload
// secrecy — hence the self-signed fallback is a safe last resort (the client
// pins it or skips verification without ever exposing tunnel data).
// ==============================================================================

package udpserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// buildStreamTLSConfig assembles the *tls.Config used by both encrypted-DNS
// listeners. h2 stays first in NextProtos so the DoH HTTP/2 server negotiates
// correctly; the DoT listener ignores ALPN. Returns an error only when provided
// cert files fail to load — the ACME and self-signed paths cannot fail closed
// here, so an enabled listener always comes up.
func (s *Server) buildStreamTLSConfig() (*tls.Config, error) {
	// 1. Operator-provided real certificate.
	if s.cfg.TLSCertFile != "" && s.cfg.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load TLS cert/key: %w", err)
		}
		s.log.Infof("\U0001F510 <green>Encrypted-DNS TLS: using provided certificate</green>")
		return &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
		}, nil
	}

	// Generate the fallback before configuring ACME. autocert obtains a
	// certificate lazily during the first handshake, so a simple control-flow
	// "fallback" after TLSConfig() can never run when issuance fails.
	fallback, err := generateSelfSignedCert(s.cfg.Domain)
	if err != nil {
		return nil, fmt.Errorf("generate self-signed cert: %w", err)
	}

	// 2. ACME / Let's Encrypt for the tunnel domain(s). The TLS-ALPN-01 challenge
	//    is answered on the same 443 TLS handshake the DoH listener already serves,
	//    so no extra port is needed. Falls through to self-signed when no domain
	//    is eligible (e.g. an IP-only deployment).
	acmeReachable := s.cfg.DoHListenerEnabled && s.cfg.DoHTLSEnabled && s.cfg.DoHListenPort == 443
	if s.cfg.ACMEEnabled && acmeReachable {
		if hosts := acmeEligibleDomains(s.cfg.Domain); len(hosts) > 0 {
			m := &autocert.Manager{
				Prompt:     autocert.AcceptTOS,
				Cache:      autocert.DirCache(s.cfg.ACMECacheDir),
				HostPolicy: autocert.HostWhitelist(hosts...),
				Email:      s.cfg.ACMEEmail,
			}
			cfg := m.TLSConfig() // installs GetCertificate + the acme-tls/1 ALPN
			cfg.MinVersion = tls.VersionTLS12
			managerGetCertificate := cfg.GetCertificate
			cfg.Certificates = []tls.Certificate{fallback}
			cfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				cert, getErr := managerGetCertificate(hello)
				if getErr == nil && cert != nil {
					return cert, nil
				}
				// Keep encrypted DNS usable when issuance/renewal is temporarily
				// unavailable. Operators can observe the event and clients may pin
				// the stable configured certificate for production deployments.
				s.tlsHandshakeFailures.Add(1)
				return &fallback, nil
			}
			s.log.Infof("\U0001F510 <green>Encrypted-DNS TLS: ACME/Let's Encrypt for <cyan>%s</cyan></green>", strings.Join(hosts, ", "))
			return cfg, nil
		}
	}

	// 3. Self-signed fallback so the listener always starts.
	s.log.Warnf("\U0001F513 <yellow>Encrypted-DNS TLS: self-signed certificate (clients must pin the fingerprint or skip verification; tunnel payload stays AEAD-encrypted regardless)</yellow>")
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{fallback},
	}, nil
}

func dotTLSConfig(base *tls.Config) *tls.Config {
	if base == nil {
		return nil
	}
	cfg := base.Clone()
	cfg.NextProtos = mergeALPN([]string{"dot"}, base.NextProtos)
	return cfg
}

func dohTLSConfig(base *tls.Config) *tls.Config {
	if base == nil {
		return nil
	}
	cfg := base.Clone()
	cfg.NextProtos = mergeALPN([]string{"h2", "http/1.1"}, base.NextProtos)
	return cfg
}

func mergeALPN(first, existing []string) []string {
	result := make([]string, 0, len(first)+len(existing))
	seen := make(map[string]struct{}, len(first)+len(existing))
	for _, group := range [][]string{first, existing} {
		for _, proto := range group {
			if proto == "" {
				continue
			}
			if _, ok := seen[proto]; ok {
				continue
			}
			seen[proto] = struct{}{}
			result = append(result, proto)
		}
	}
	return result
}

// acmeEligibleDomains keeps only entries Let's Encrypt can actually issue for:
// real DNS names, no IPs and no wildcards (which need DNS-01, not TLS-ALPN-01).
func acmeEligibleDomains(domains []string) []string {
	out := make([]string, 0, len(domains))
	for _, d := range domains {
		d = strings.TrimSpace(strings.TrimSuffix(d, "."))
		if d == "" || strings.Contains(d, "*") || strings.Contains(d, "/") {
			continue
		}
		if net.ParseIP(d) != nil {
			continue // an IP literal is not ACME-issuable
		}
		if !strings.Contains(d, ".") {
			continue // needs at least one dot to be a public name
		}
		out = append(out, d)
	}
	return out
}

// generateSelfSignedCert mints an in-memory ECDSA P-256 certificate covering the
// tunnel domains (DNS SANs) plus any IP literals among them (IP SANs), so a
// client connecting by domain or by raw IP can still validate/pin it.
func generateSelfSignedCert(domains []string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: firstNonEmpty(domains, "cottendns.local")},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, d := range domains {
		d = strings.TrimSpace(strings.TrimSuffix(d, "."))
		if d == "" {
			continue
		}
		if ip := net.ParseIP(d); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, d)
		}
	}
	if len(tmpl.DNSNames) == 0 && len(tmpl.IPAddresses) == 0 {
		tmpl.DNSNames = []string{"cottendns.local"}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: tmpl}, nil
}

func firstNonEmpty(values []string, fallback string) string {
	for _, v := range values {
		if s := strings.TrimSpace(strings.TrimSuffix(v, ".")); s != "" {
			return s
		}
	}
	return fallback
}
