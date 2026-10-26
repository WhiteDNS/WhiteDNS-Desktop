package soar

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

const (
	sampleLen = 12
	pubLen    = 32
	sigLen    = ed25519.SignatureSize
	// helloReplyLen is serverEph || sid || signature.
	helloReplyLen = pubLen + 2 + sigLen

	sigContext = "soar v1 hello"
	// unknownContext domain-separates the server's signed "no such session" reply.
	unknownContext = "soar v1 unknown session"
	kdfLabel       = "soar v1 "
)

var (
	errAuth         = errors.New("soar: packet authentication failed")
	errBadSignature = errors.New("soar: server signature verification failed")
)

// sessionCiphers derives both directions' ciphers from the ephemeral-ephemeral secret, salted with
// the handshake transcript.
func sessionCiphers(ee, transcript []byte) (up, down *packetCipher, err error) {
	prk, err := hkdf.Extract(sha256.New, ee, transcript)
	if err != nil {
		return nil, nil, err
	}
	if up, err = newCipher(prk, "up"); err != nil {
		return nil, nil, err
	}
	down, err = newCipher(prk, "down")
	return up, down, err
}

// downAD is a downstream packet's associated data: its truncated packet number on the wire, and,
// implicitly, the upstream packet number of the query it answers, so a valid answer can't be
// replayed onto another query (which would falsely acknowledge that query's data).
func downAD(trunc [2]byte, upPN uint64) []byte {
	return binary.BigEndian.AppendUint64(trunc[:], upPN)
}

// sealUp builds an upstream packet: the session id, the protected truncated packet number, and
// the sealed plaintext. The associated data is the session id and the truncated packet number
// unmasked; on the wire the packet number is masked.
func (c *packetCipher) sealUp(sid uint16, pn uint64, plain []byte) []byte {
	var hdr [4]byte
	binary.BigEndian.PutUint16(hdr[:], sid)
	binary.BigEndian.PutUint16(hdr[2:], uint16(pn))
	sealed := c.seal(nil, hdr[:], plain, pn)
	m := c.mask(sealed)
	p := make([]byte, 0, len(hdr)+len(sealed))
	p = append(p, hdr[0], hdr[1], hdr[2]^m[0], hdr[3]^m[1])
	return append(p, sealed...)
}

// openUp authenticates the upstream packet p, expanding its truncated packet number with decode.
func (c *packetCipher) openUp(p []byte, decode func(uint16) uint64) (pn uint64, plain []byte, err error) {
	if len(p) < 4+sampleLen {
		return 0, nil, errAuth
	}
	sealed := p[4:]
	m := c.mask(sealed)
	hdr := [4]byte{p[0], p[1], p[2] ^ m[0], p[3] ^ m[1]}
	pn = decode(binary.BigEndian.Uint16(hdr[2:]))
	plain, err = c.open(hdr[:], sealed, pn)
	return pn, plain, err
}

// sealDown builds a downstream packet answering the query that carried upstream packet upPN: the
// protected truncated packet number, then the sealed plaintext.
func (c *packetCipher) sealDown(pn, upPN uint64, plain []byte) []byte {
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(pn))
	sealed := c.seal(nil, downAD(hdr, upPN), plain, pn)
	m := c.mask(sealed)
	p := make([]byte, 0, len(hdr)+len(sealed))
	p = append(p, hdr[0]^m[0], hdr[1]^m[1])
	return append(p, sealed...)
}

// openDown authenticates the downstream packet p as the answer to upstream packet upPN.
func (c *packetCipher) openDown(p []byte, upPN uint64, decode func(uint16) uint64) (pn uint64, plain []byte, err error) {
	if len(p) < 2+sampleLen {
		return 0, nil, errAuth
	}
	sealed := p[2:]
	m := c.mask(sealed)
	hdr := [2]byte{p[0] ^ m[0], p[1] ^ m[1]}
	pn = decode(binary.BigEndian.Uint16(hdr[:]))
	plain, err = c.open(downAD(hdr, upPN), sealed, pn)
	return pn, plain, err
}

// unknownSessionMsg is what the server signs to say a query's session doesn't exist: the
// question, lower-cased since resolvers may randomize case on the way to us. Only ASCII letters
// are folded, so every implementation signs the same bytes whatever the question holds.
func unknownSessionMsg(question []byte) []byte {
	m := append([]byte(unknownContext), question...)
	for i := len(unknownContext); i < len(m); i++ {
		if c := m[i]; 'A' <= c && c <= 'Z' {
			m[i] = c + 'a' - 'A'
		}
	}
	return m
}

func transcript(clientEph, serverEph []byte, sid uint16) []byte {
	t := make([]byte, 0, len(sigContext)+2*pubLen+2)
	t = append(t, sigContext...)
	t = append(t, clientEph...)
	t = append(t, serverEph...)
	return binary.BigEndian.AppendUint16(t, sid)
}

// serverHello answers a client's ephemeral key: it returns the reply bytes and the session ciphers.
func serverHello(priv ed25519.PrivateKey, clientEph []byte, sid uint16) (reply []byte, up, down *packetCipher, err error) {
	cpub, err := ecdh.X25519().NewPublicKey(clientEph)
	if err != nil {
		return nil, nil, nil, err
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	return serverHelloWith(priv, eph, cpub, sid)
}

// serverHelloWith is serverHello with the server's ephemeral key given.
func serverHelloWith(priv ed25519.PrivateKey, eph *ecdh.PrivateKey, cpub *ecdh.PublicKey, sid uint16) (reply []byte, up, down *packetCipher, err error) {
	clientEph := cpub.Bytes()
	ee, err := eph.ECDH(cpub)
	if err != nil {
		return nil, nil, nil, err
	}
	tr := transcript(clientEph, eph.PublicKey().Bytes(), sid)
	if up, down, err = sessionCiphers(ee, tr); err != nil {
		return nil, nil, nil, err
	}
	reply = append(eph.PublicKey().Bytes(), byte(sid>>8), byte(sid))
	return append(reply, ed25519.Sign(priv, tr)...), up, down, nil
}

// clientFinish verifies the server's hello reply and derives the session.
func clientFinish(pub ed25519.PublicKey, eph *ecdh.PrivateKey, reply []byte) (sid uint16, up, down *packetCipher, err error) {
	if len(reply) < helloReplyLen {
		return 0, nil, nil, errBadSignature
	}
	seph := reply[:pubLen]
	sid = binary.BigEndian.Uint16(reply[pubLen:])
	tr := transcript(eph.PublicKey().Bytes(), seph, sid)
	if !ed25519.Verify(pub, tr, reply[pubLen+2:helloReplyLen]) {
		return 0, nil, nil, errBadSignature
	}
	spub, err := ecdh.X25519().NewPublicKey(seph)
	if err != nil {
		return 0, nil, nil, err
	}
	ee, err := eph.ECDH(spub)
	if err != nil {
		return 0, nil, nil, err
	}
	up, down, err = sessionCiphers(ee, tr)
	return sid, up, down, err
}
