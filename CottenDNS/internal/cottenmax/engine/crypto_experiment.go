//go:build maxexperiment

package soar

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"
)

// These process-wide values exist only in a maxexperiment build. Select the suite
// before constructing any client or server, and close all endpoints before changing
// it. Neither suite negotiation nor production configuration is implemented here.
var (
	experimentCipherName = "chacha20-poly1305-8"
	tagLen               = 8
	minPlain             = sampleLen - tagLen
)

// ExperimentCipherNames lists authenticated laboratory suites. The original
// eight-byte-tag ChaCha suite is first and remains the default.
func ExperimentCipherNames() []string {
	return []string{"chacha20-poly1305-8", "chacha20-poly1305-8-stacktag", "aes-128-gcm-12", "aes-256-gcm-12", "aes-128-gcm-16", "chacha20-poly1305-16"}
}

// SetExperimentCipher selects the same cipher on both matched laboratory endpoints.
// It must not be called concurrently with, or during the lifetime of, any endpoint.
// Alternative suites deliberately derive different traffic keys; they cannot talk
// to released CottenMax servers. This API is absent from ordinary builds.
func SetExperimentCipher(name string) error {
	size := 0
	switch name {
	case "chacha20-poly1305-8", "chacha20-poly1305-8-stacktag":
		size = 8
	case "aes-128-gcm-12", "aes-256-gcm-12":
		size = 12
	case "chacha20-poly1305-16", "aes-128-gcm-16":
		size = 16
	default:
		return fmt.Errorf("unknown CottenMax experiment cipher %q", name)
	}
	experimentCipherName, tagLen = name, size
	minPlain = max(0, sampleLen-tagLen)
	return nil
}

// ExperimentCipherInfo reports the selected laboratory suite and wire tag size.
func ExperimentCipherInfo() (name string, tagBytes int) { return experimentCipherName, tagLen }

// packetCipher is the laboratory implementation. The baseline retains its exact
// truncated-tag ChaCha construction; alternatives use Go AEAD implementations.
// All suites retain ChaCha header protection to isolate traffic-AEAD costs.
type packetCipher struct {
	key      [32]byte
	iv       [12]byte
	hp       [32]byte
	aead     cipher.AEAD
	stackTag bool
}

func (c *packetCipher) nonce(pn uint64) []byte {
	n := c.iv
	for i := range 8 {
		n[4+i] ^= byte(pn >> (56 - 8*i))
	}
	return n[:]
}

// seal appends the encryption of plain and its tag to dst.
func (c *packetCipher) seal(dst, ad, plain []byte, pn uint64) []byte {
	if c.aead != nil {
		return c.aead.Seal(dst, c.nonce(pn), plain, ad)
	}
	s, _ := chacha20.NewUnauthenticatedCipher(c.key[:], c.nonce(pn))
	start := len(dst)
	dst = append(dst, plain...)
	ct := dst[start:]
	// The Poly1305 key is block 0; the payload starts at block 1.
	var block0 [64]byte
	s.XORKeyStream(block0[:], block0[:])
	s.XORKeyStream(ct, ct)
	if c.stackTag {
		var tag [16]byte
		c.tagInto(&tag, block0[:32], ad, ct)
		return append(dst, tag[:8]...)
	}
	return append(dst, c.tagFrom(block0[:32], ad, ct)...)
}

func (c *packetCipher) tagFrom(polyKey, ad, ct []byte) []byte {
	var k [32]byte
	copy(k[:], polyKey)
	m := poly1305.New(&k)
	var pad [16]byte
	m.Write(ad)
	m.Write(pad[:(16-len(ad)%16)%16])
	m.Write(ct)
	m.Write(pad[:(16-len(ct)%16)%16])
	var lens [16]byte
	binary.LittleEndian.PutUint64(lens[:8], uint64(len(ad)))
	binary.LittleEndian.PutUint64(lens[8:], uint64(len(ct)))
	m.Write(lens[:])
	return m.Sum(nil)[:tagLen]
}

// open authenticates and decrypts ct||tag, returning a new plaintext slice.
func (c *packetCipher) open(ad, sealed []byte, pn uint64) ([]byte, error) {
	if c.aead != nil {
		p, err := c.aead.Open(nil, c.nonce(pn), sealed, ad)
		if err != nil {
			return nil, errAuth
		}
		return p, nil
	}
	if len(sealed) < tagLen {
		return nil, errAuth
	}
	ct, tag := sealed[:len(sealed)-tagLen], sealed[len(sealed)-tagLen:]
	s, _ := chacha20.NewUnauthenticatedCipher(c.key[:], c.nonce(pn))
	var block0 [64]byte
	s.XORKeyStream(block0[:], block0[:])
	computed := []byte(nil)
	var stack [16]byte
	if c.stackTag {
		c.tagInto(&stack, block0[:32], ad, ct)
		computed = stack[:8]
	} else {
		computed = c.tagFrom(block0[:32], ad, ct)
	}
	if subtle.ConstantTimeCompare(computed, tag) != 1 {
		return nil, errAuth
	}
	plain := make([]byte, len(ct))
	s.XORKeyStream(plain, ct)
	return plain, nil
}

// mask returns the 2-byte packet-number mask for a ciphertext sample.
func (c *packetCipher) mask(sample []byte) [2]byte {
	s, _ := chacha20.NewUnauthenticatedCipher(c.hp[:], sample[:sampleLen])
	var m [2]byte
	s.XORKeyStream(m[:], m[:])
	return m
}

func newCipher(prk []byte, dir string) (*packetCipher, error) {
	c := &packetCipher{stackTag: experimentCipherName == "chacha20-poly1305-8-stacktag"}
	labelPrefix := kdfLabel
	if experimentCipherName != "chacha20-poly1305-8" && !c.stackTag {
		labelPrefix += "experiment " + experimentCipherName + " "
	}
	for _, f := range []struct {
		dst   []byte
		label string
	}{{c.key[:], "key"}, {c.iv[:], "iv"}, {c.hp[:], "hp"}} {
		b, err := hkdf.Expand(sha256.New, prk, labelPrefix+dir+" "+f.label, len(f.dst))
		if err != nil {
			return nil, err
		}
		copy(f.dst, b)
	}
	switch experimentCipherName {
	case "aes-128-gcm-12", "aes-256-gcm-12", "aes-128-gcm-16":
		size := 32
		if experimentCipherName != "aes-256-gcm-12" {
			size = 16
		}
		block, err := aes.NewCipher(c.key[:size])
		if err != nil {
			return nil, err
		}
		c.aead, err = cipher.NewGCMWithTagSize(block, tagLen)
		if err != nil {
			return nil, err
		}
	case "chacha20-poly1305-16":
		var err error
		c.aead, err = chacha20poly1305.New(c.key[:])
		if err != nil {
			return nil, err
		}
	}
	return c, nil
}

// tagInto preserves the exact RFC 8439 MAC input and the existing eight-byte
// truncation. Its only difference is writing the full tag into caller storage.
func (c *packetCipher) tagInto(out *[16]byte, polyKey, ad, ct []byte) {
	var k [32]byte
	copy(k[:], polyKey)
	m := poly1305.New(&k)
	var pad [16]byte
	m.Write(ad)
	m.Write(pad[:(16-len(ad)%16)%16])
	m.Write(ct)
	m.Write(pad[:(16-len(ct)%16)%16])
	var lens [16]byte
	binary.LittleEndian.PutUint64(lens[:8], uint64(len(ad)))
	binary.LittleEndian.PutUint64(lens[8:], uint64(len(ct)))
	m.Write(lens[:])
	m.Sum(out[:0])
}
