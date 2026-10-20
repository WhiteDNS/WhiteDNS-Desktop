// Package cottenmax adapts a pinned Soar transport for experimental CottenDNS
// sessions. The legacy protocol never passes through this package.
package cottenmax

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

const Label = "cottenmax-v1"

// SharedIdentity isolates Max's signing identity from the existing CottenDNS
// shared credential. Session encryption still uses fresh ephemeral X25519 keys.
// Holders of the shared credential share the trust boundary, as in legacy mode.
func SharedIdentity(secret string) (ed25519.PrivateKey, error) {
	if strings.TrimSpace(secret) == "" {
		return nil, errors.New("cottenmax: CottenDNS shared credential is required")
	}
	seed, err := hkdf.Key(sha256.New, []byte(secret), nil, "CottenDNS CottenMax signing identity v1", ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func Zone(domain string) string { return Label + "." + strings.ToLower(strings.Trim(domain, ". ")) }

// LoadKey never replaces an existing malformed key or silently changes identity.
func LoadKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		_, key, genErr := ed25519.GenerateKey(rand.Reader)
		if genErr != nil {
			return nil, genErr
		}
		f, createErr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if createErr != nil {
			return nil, createErr
		}
		_, writeErr := f.WriteString(base64.StdEncoding.EncodeToString(key.Seed()) + "\n")
		closeErr := f.Close()
		if writeErr != nil {
			return nil, writeErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		return key, nil
	}
	if err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid CottenMax signing key %s", path)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// The public signing key authenticates the server; it is not an access token.
// Retain shared-secret access control with a destination-bound MAC inside the
// encrypted stream-open descriptor (23 bytes once per stream).
func targetTag(secret, target string) []byte {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte("CottenMax stream admission v1\x00"))
	h.Write([]byte(target))
	return h.Sum(nil)[:16]
}

func signTarget(secret, target string) string {
	return base64.RawURLEncoding.EncodeToString(targetTag(secret, target)) + "@" + target
}

func verifyTarget(secret, signed string) (string, error) {
	tagText, target, ok := strings.Cut(signed, "@")
	tag, err := base64.RawURLEncoding.DecodeString(tagText)
	if !ok || err != nil || !hmac.Equal(tag, targetTag(secret, target)) {
		return "", errors.New("cottenmax: stream admission failed")
	}
	return target, nil
}
