package client

import (
	"crypto/sha256"
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"time"

	DnsParser "cottendns-go/internal/dnsparser"
	"cottendns-go/internal/security"
	VpnProto "cottendns-go/internal/vpnproto"
)

const (
	downstreamReplayMaxEntries = 8192
	downstreamReplayTTL        = 5 * time.Minute
)

type downstreamReplayEntry struct {
	digest  [sha256.Size]byte
	expires time.Time
}

// downstreamReplayCache suppresses repeated authenticated response ciphertext,
// independent of DNS transaction IDs, resolver paths and carrier encodings.
// It retains at most 8192 responses for at most five minutes. Freshly encrypted
// ARQ retransmissions remain valid, so dropped ACKs can still be recovered.
// Canonical-question AEAD binding also prevents old captured responses from
// being moved onto a new query after their cache entry has expired.
type downstreamReplayCache struct {
	mu    sync.Mutex
	seen  map[[sha256.Size]byte]time.Time
	order []downstreamReplayEntry
	next  int
	limit int
	ttl   time.Duration
}

func (c *downstreamReplayCache) accept(digest [sha256.Size]byte, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen == nil {
		if c.limit <= 0 {
			c.limit = downstreamReplayMaxEntries
		}
		if c.ttl <= 0 {
			c.ttl = downstreamReplayTTL
		}
		c.seen = make(map[[sha256.Size]byte]time.Time)
		c.order = make([]downstreamReplayEntry, c.limit)
	}
	if expires, ok := c.seen[digest]; ok && now.Before(expires) {
		return false
	}
	old := c.order[c.next]
	if expires, ok := c.seen[old.digest]; ok && expires == old.expires {
		delete(c.seen, old.digest)
	}
	expires := now.Add(c.ttl)
	c.seen[digest] = expires
	c.order[c.next] = downstreamReplayEntry{digest: digest, expires: expires}
	c.next = (c.next + 1) % len(c.order)
	return true
}

// acceptDownstreamPacketReplay runs after authenticated decode and session
// validation, and before activity, ACK or stream handlers. Only a pending query
// from this resolver/socket can claim a response; ID reuse must also match the
// complete canonical question. Claiming the sample atomically (via
// claimResolverSuccessSample, shared with trackResolverSuccess) prevents two
// concurrent workers from both dispatching responses for the same query, and
// means an authenticated response's question digest is hashed and its pending
// sample looked up exactly once, not once here and again in trackResolverSuccess.
//
// handled reports whether success bookkeeping (carrier credit, RTT sample) was
// already applied, so the caller must skip its own trackResolverSuccess call
// when handled is true — calling it again would find nothing left to claim.
func (c *Client) acceptDownstreamPacketReplay(data []byte, addr *net.UDPAddr, localAddr string, packet VpnProto.Packet) (accepted, handled bool) {
	if !c.encryptedDownstream() || !security.IsAuthenticatedMethod(c.codec.Method()) {
		return true, false
	}
	if !packet.HasDownstreamCiphertext || addr == nil || len(data) < 2 {
		return false, false
	}

	sample, ok := c.claimResolverSuccessSample(data, addr, localAddr)

	if !ok || !sample.questionKnown {
		return false, false
	}

	now := time.Now()
	if !c.downstreamReplay.accept(packet.DownstreamCiphertextHash, now) {
		// An identical query can be fanned over several resolvers. Every real
		// pending path deserves its own delivery credit, while the response's
		// control/session side effects must run only once.
		c.applyResolverSuccess(sample, data, now)
		return false, true
	}
	c.applyResolverSuccess(sample, data, now)
	return true, true
}

// resolverQuestionDigest ignores ID, DNS name case and name compression while
// retaining every question's name, type and class. A hash keeps pending samples
// bounded even when QNAMEs contain the maximum-length encrypted tunnel frame.
func resolverQuestionDigest(data []byte) ([sha256.Size]byte, bool) {
	parsed, err := DnsParser.ParsePacketLite(data)
	if err != nil || !parsed.HasQuestion {
		return [sha256.Size]byte{}, false
	}
	hash := sha256.New()
	var fields [6]byte
	binary.BigEndian.PutUint16(fields[:2], uint16(len(parsed.Questions)))
	_, _ = hash.Write(fields[:2])
	for _, question := range parsed.Questions {
		name := strings.ToLower(strings.TrimSuffix(question.Name, "."))
		binary.BigEndian.PutUint16(fields[:2], uint16(len(name)))
		binary.BigEndian.PutUint16(fields[2:4], question.Type)
		binary.BigEndian.PutUint16(fields[4:6], question.Class)
		_, _ = hash.Write(fields[:])
		_, _ = hash.Write([]byte(name))
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest, true
}
