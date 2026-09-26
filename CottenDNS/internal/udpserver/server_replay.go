package udpserver

import (
	"container/list"
	"crypto/sha256"
	"sync"
	"time"

	baseCodec "cottendns-go/internal/basecodec"
	DnsParser "cottendns-go/internal/dnsparser"
	domainMatcher "cottendns-go/internal/domainmatcher"
	"cottendns-go/internal/security"
	VpnProto "cottendns-go/internal/vpnproto"
)

const (
	ingressReplayMaxEntries = 8192
	ingressReplayMaxBytes   = 16 * 1024 * 1024
	ingressReplayTTL        = 5 * time.Minute
)

type ingressReplayKey struct {
	ciphertext [sha256.Size]byte
	method     int
}

type ingressReplayEntry struct {
	key       ingressReplayKey
	query     [sha256.Size]byte
	response  []byte
	expiresAt time.Time
	completed *list.Element
}

// ingressReplayCache gives authenticated ciphertext at-most-once dispatch while
// retaining replies for ordinary DNS retries. Its protection is intentionally
// bounded: completed requests age out after five minutes or 8192 newer entries.
// Keys survive response-byte pressure, so a missing cached reply never causes a
// retained ciphertext to be dispatched again. Process restarts reset the cache.
// Legacy unauthenticated methods cannot make a meaningful replay guarantee and
// are left unchanged. The zero value is ready to use.
//
// Never put this check in Codec.Decrypt: codec trials, admission and transport
// retries may decrypt the same request more than once before it is dispatched.
// ARQ retransmissions encrypt anew and therefore remain independent requests.
type ingressReplayCache struct {
	mu         sync.Mutex
	entries    map[ingressReplayKey]*ingressReplayEntry
	completed  list.List
	bytes      int
	maxEntries int
	maxBytes   int
	ttl        time.Duration
}

func (c *ingressReplayCache) begin(key ingressReplayKey, query [sha256.Size]byte, now time.Time) (*ingressReplayEntry, []byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[ingressReplayKey]*ingressReplayEntry)
		if c.maxEntries <= 0 {
			c.maxEntries = ingressReplayMaxEntries
		}
		if c.maxBytes <= 0 {
			c.maxBytes = ingressReplayMaxBytes
		}
		if c.ttl <= 0 {
			c.ttl = ingressReplayTTL
		}
	}
	for oldest := c.completed.Front(); oldest != nil; oldest = c.completed.Front() {
		entry := oldest.Value.(*ingressReplayEntry)
		if now.Before(entry.expiresAt) {
			break
		}
		c.remove(entry)
	}
	if entry := c.entries[key]; entry != nil {
		if entry.query == query && entry.completed != nil {
			return nil, append([]byte(nil), entry.response...), false
		}
		// A concurrent duplicate never waits on a worker: the first request may
		// itself need scarce worker/queue resources to finish. A later retry can
		// retrieve its completed response. Changed questions cannot run it again.
		return nil, nil, false
	}
	for len(c.entries) >= c.maxEntries {
		oldest := c.completed.Front()
		if oldest == nil {
			// All slots are in flight. Fail closed without evicting their guards.
			return nil, nil, false
		}
		c.remove(oldest.Value.(*ingressReplayEntry))
	}
	entry := &ingressReplayEntry{key: key, query: query}
	c.entries[key] = entry
	return entry, nil, true
}

func (c *ingressReplayCache) finish(entry *ingressReplayEntry, response []byte, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(response) <= c.maxBytes {
		for oldest := c.completed.Front(); c.bytes+len(response) > c.maxBytes && oldest != nil; oldest = oldest.Next() {
			previous := oldest.Value.(*ingressReplayEntry)
			c.bytes -= len(previous.response)
			previous.response = nil
		}
		entry.response = append([]byte(nil), response...)
		c.bytes += len(entry.response)
	}
	entry.expiresAt = now.Add(c.ttl)
	entry.completed = c.completed.PushBack(entry)
}

// remove is called with mu held and only for completed entries.
func (c *ingressReplayCache) remove(entry *ingressReplayEntry) {
	delete(c.entries, entry.key)
	c.bytes -= len(entry.response)
	c.completed.Remove(entry.completed)
}

func (s *Server) handleReplayProtectedPacket(request []byte, parsed DnsParser.LitePacket, decision domainMatcher.Decision, packet VpnProto.Packet, dispatch func() []byte) (response []byte) {
	if packet.IngressCodec == nil || !security.IsAuthenticatedMethod(packet.IngressCodec.Method()) {
		return dispatch()
	}
	// Hash decoded ciphertext, not its DNS spelling: case and alternate base
	// encodings must not turn an already authenticated frame into a new request.
	ciphertext, err := baseCodec.DecodeString(decision.Labels)
	if err != nil {
		return s.buildNoDataResponseLiteLogged(request, parsed, "replay-key-decode-failed")
	}
	key := ingressReplayKey{ciphertext: sha256.Sum256(ciphertext), method: packet.IngressCodec.Method()}
	entry, cached, fresh := s.ingressReplay.begin(key, ingressReplayQueryHash(request, parsed), time.Now())
	if !fresh {
		if len(cached) >= parsed.QuestionEndOffset && len(request) >= parsed.QuestionEndOffset && len(cached) >= 12 {
			copy(cached[:2], request[:2])
			// Matching questions differ only in DNS letter case, which resolvers
			// may randomize and validate. Pointers/record offsets stay unchanged.
			copy(cached[12:parsed.QuestionEndOffset], request[12:parsed.QuestionEndOffset])
			return cached
		}
		return s.buildNoDataResponseLiteLogged(request, parsed, "authenticated-query-replay")
	}
	// Also complete the guard during panic unwinding. The outer safe handler
	// owns recovery, but a repeated request must not rerun partially done work.
	defer func() { s.ingressReplay.finish(entry, response, time.Now()) }()
	return dispatch()
}

// ingressReplayQueryHash binds cached replies to the entire query except its
// transaction ID and uncompressed question-name case. In particular, changing
// qtype, domain, EDNS cookie/size or flags cannot reuse a mismatched response.
func ingressReplayQueryHash(request []byte, parsed DnsParser.LitePacket) [sha256.Size]byte {
	if len(request) < 12 {
		return sha256.Sum256(request)
	}
	normalized := append([]byte(nil), request[2:]...)
	offset := 12
	for q := 0; q < int(parsed.Header.QDCount); q++ {
		for {
			if offset >= len(request) {
				return sha256.Sum256(request[2:])
			}
			length := int(request[offset])
			offset++
			if length == 0 {
				break
			}
			if length > 63 || offset+length > len(request) {
				// Compressed questions require an exact wire match so we never
				// confuse a name pointer with a letter or rewrite its target.
				return sha256.Sum256(request[2:])
			}
			for end := offset + length; offset < end; offset++ {
				if value := request[offset]; value >= 'A' && value <= 'Z' {
					normalized[offset-2] = value + ('a' - 'A')
				}
			}
		}
		offset += 4 // QTYPE and QCLASS retain their exact bytes.
	}
	return sha256.Sum256(normalized)
}
