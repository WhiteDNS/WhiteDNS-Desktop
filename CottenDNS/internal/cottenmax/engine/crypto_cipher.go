//go:build !maxexperiment

package soar

import (
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/poly1305"
)

const (
	tagLen   = 8 // Original CottenMax wire format; the experiment does not alter ordinary builds.
	minPlain = sampleLen - tagLen
)

// packetCipher seals one direction's packets: ChaCha20-Poly1305 (RFC 8439) with the tag truncated
// to 8 bytes, a per-packet nonce derived from the packet number, and QUIC-style protection of the
// truncated packet number so it doesn't appear as a counter on the wire.
type packetCipher struct {
	key [32]byte
	iv  [12]byte
	hp  [32]byte
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
	s, _ := chacha20.NewUnauthenticatedCipher(c.key[:], c.nonce(pn))
	start := len(dst)
	dst = append(dst, plain...)
	ct := dst[start:]
	// The Poly1305 key is block 0; the payload starts at block 1.
	var block0 [64]byte
	s.XORKeyStream(block0[:], block0[:])
	s.XORKeyStream(ct, ct)
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
	if len(sealed) < tagLen {
		return nil, errAuth
	}
	ct, tag := sealed[:len(sealed)-tagLen], sealed[len(sealed)-tagLen:]
	s, _ := chacha20.NewUnauthenticatedCipher(c.key[:], c.nonce(pn))
	var block0 [64]byte
	s.XORKeyStream(block0[:], block0[:])
	if subtle.ConstantTimeCompare(c.tagFrom(block0[:32], ad, ct), tag) != 1 {
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
	c := &packetCipher{}
	for _, f := range []struct {
		dst   []byte
		label string
	}{{c.key[:], "key"}, {c.iv[:], "iv"}, {c.hp[:], "hp"}} {
		b, err := hkdf.Expand(sha256.New, prk, kdfLabel+dir+" "+f.label, len(f.dst))
		if err != nil {
			return nil, err
		}
		copy(f.dst, b)
	}
	return c, nil
}
