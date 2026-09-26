package udpserver

import (
	"bytes"
	"encoding/binary"
	"sync/atomic"
	"testing"
	"time"

	DnsParser "cottendns-go/internal/dnsparser"
	domainMatcher "cottendns-go/internal/domainmatcher"
	Enums "cottendns-go/internal/enums"
	"cottendns-go/internal/security"
	VpnProto "cottendns-go/internal/vpnproto"
)

func replayTestQuery(t *testing.T, method int) (*Server, []byte, preparedIngress) {
	t.Helper()
	codec, err := security.NewCodec(method, "replay-test-shared-key")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{domainMatcher: domainMatcher.New([]string{"v.example.com"}, 3), codecs: []*security.Codec{codec}}
	query := buildReplayTestQuery(t, codec)
	prepared, ok := s.prepareIngressPacket(query)
	if !ok {
		t.Fatal("query was not admitted")
	}
	return s, query, prepared
}

func buildReplayTestQuery(t *testing.T, codec *security.Codec) []byte {
	t.Helper()
	encoded, err := VpnProto.BuildEncoded(VpnProto.BuildOptions{
		SessionID: 255, PacketType: Enums.PACKET_MTU_UP_REQ, Payload: []byte{0, 1, 2, 3, 4},
	}, codec)
	if err != nil {
		t.Fatal(err)
	}
	query, err := DnsParser.BuildTunnelTXTQuestionPacket("v.example.com", []byte(encoded), Enums.DNS_RECORD_TYPE_TXT, 1232)
	if err != nil {
		t.Fatal(err)
	}
	return query
}

func TestAuthenticatedIngressReplayReusesReplyWithoutDispatch(t *testing.T) {
	s, query, prepared := replayTestQuery(t, 5)
	calls := 0
	dispatch := func() []byte {
		calls++
		response, err := DnsParser.BuildEmptyNoErrorResponse(query)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	first := s.handleReplayProtectedPacket(query, prepared.parsed, prepared.decision, prepared.packet, dispatch)
	retry := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(retry[:2], binary.BigEndian.Uint16(query[:2])+1)
	for offset := 12; offset < prepared.parsed.QuestionEndOffset-4; offset++ {
		if retry[offset] >= 'a' && retry[offset] <= 'z' {
			retry[offset] -= 'a' - 'A'
		}
	}
	retryPrepared, ok := s.prepareIngressPacket(retry)
	if !ok {
		t.Fatal("case-randomized retry was not admitted")
	}
	second := s.handleReplayProtectedPacket(retry, retryPrepared.parsed, retryPrepared.decision, retryPrepared.packet, dispatch)
	if calls != 1 {
		t.Fatalf("duplicate request dispatched %d times", calls)
	}
	if !bytes.Equal(second[:2], retry[:2]) || !bytes.Equal(second[12:prepared.parsed.QuestionEndOffset], retry[12:prepared.parsed.QuestionEndOffset]) {
		t.Fatal("cached reply did not echo retry ID and question case")
	}
	if !bytes.Equal(first[:2], query[:2]) || !bytes.Equal(first[12:prepared.parsed.QuestionEndOffset], query[12:prepared.parsed.QuestionEndOffset]) {
		t.Fatal("reply reuse mutated the first response")
	}
	// A carrier change must not let captured authenticated ciphertext consume
	// another queued response or repeat its control/session side effects.
	altered := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(altered[prepared.parsed.QuestionEndOffset-4:], Enums.DNS_RECORD_TYPE_AAAA)
	alteredPrepared, ok := s.prepareIngressPacket(altered)
	if !ok {
		t.Fatal("changed carrier was not admitted")
	}
	response := s.handleReplayProtectedPacket(altered, alteredPrepared.parsed, alteredPrepared.decision, alteredPrepared.packet, dispatch)
	parsed, err := DnsParser.ParsePacketLite(response)
	if err != nil || parsed.Header.ANCount != 0 || parsed.Header.RCode != 0 {
		t.Fatalf("changed query should receive NODATA: packet=%+v err=%v", parsed.Header, err)
	}
	if calls != 1 {
		t.Fatal("changing qtype bypassed the replay guard")
	}
}

func TestIngressReplayAllowsFreshARQEncryptionAndLegacyRepeats(t *testing.T) {
	for _, method := range []int{1, 5} {
		s, query, prepared := replayTestQuery(t, method)
		calls := 0
		dispatch := func() []byte { calls++; return nil }
		s.handleReplayProtectedPacket(query, prepared.parsed, prepared.decision, prepared.packet, dispatch)
		if method == 5 {
			// Identical plaintext with a fresh AEAD nonce is an ARQ retry, not
			// a captured-ciphertext replay. Admission itself consumes no nonce.
			query = buildReplayTestQuery(t, s.codecs[0])
			var ok bool
			prepared, ok = s.prepareIngressPacket(query)
			if !ok {
				t.Fatal("fresh retransmission was not admitted")
			}
		}
		s.handleReplayProtectedPacket(query, prepared.parsed, prepared.decision, prepared.packet, dispatch)
		if calls != 2 {
			t.Fatalf("method %d retransmission dispatched %d times, want 2", method, calls)
		}
	}
}

func TestIngressReplayConcurrentDuplicateDoesNotWait(t *testing.T) {
	s, query, prepared := replayTestQuery(t, 5)
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	go func() {
		defer close(done)
		s.handleReplayProtectedPacket(query, prepared.parsed, prepared.decision, prepared.packet, func() []byte {
			calls.Add(1)
			close(started)
			<-release
			return nil
		})
	}()
	<-started
	duplicateDone := make(chan struct{})
	go func() {
		defer close(duplicateDone)
		s.handleReplayProtectedPacket(query, prepared.parsed, prepared.decision, prepared.packet, func() []byte { calls.Add(1); return nil })
	}()
	select {
	case <-duplicateDone:
	case <-time.After(time.Second):
		close(release)
		<-done
		t.Fatal("duplicate blocked behind in-flight request")
	}
	close(release)
	<-done
	if calls.Load() != 1 {
		t.Fatal("concurrent replay repeated dispatch")
	}
}

func TestIngressReplayCacheRetainsKeysWhenReplyBytesFill(t *testing.T) {
	cache := ingressReplayCache{maxEntries: 2, maxBytes: 4, ttl: time.Minute}
	now := time.Unix(100, 0)
	key1, key2 := ingressReplayKey{method: 3}, ingressReplayKey{method: 5}
	query := [32]byte{1}
	entry, _, fresh := cache.begin(key1, query, now)
	if !fresh {
		t.Fatal("first entry rejected")
	}
	cache.finish(entry, []byte("1234"), now)
	entry, _, fresh = cache.begin(key2, query, now)
	if !fresh {
		t.Fatal("second entry rejected")
	}
	cache.finish(entry, []byte("abcd"), now)
	if _, response, fresh := cache.begin(key1, query, now); fresh || len(response) != 0 {
		t.Fatal("response-byte pressure removed replay key or kept excess bytes")
	}
	if cache.bytes != 4 || len(cache.entries) != 2 {
		t.Fatalf("cache limits: bytes=%d entries=%d", cache.bytes, len(cache.entries))
	}
	if _, _, fresh := cache.begin(key1, query, now.Add(time.Minute)); !fresh {
		t.Fatal("expired replay key was never released")
	}
}

func TestIngressReplayCacheNeverEvictsInflightRequest(t *testing.T) {
	cache := ingressReplayCache{maxEntries: 1}
	now := time.Now()
	key1, key2 := ingressReplayKey{method: 3}, ingressReplayKey{method: 5}
	query := [32]byte{1}
	entry, _, fresh := cache.begin(key1, query, now)
	if !fresh {
		t.Fatal("first entry rejected")
	}
	if _, _, fresh = cache.begin(key2, query, now); fresh {
		t.Fatal("in-flight replay guard was evicted")
	}
	cache.finish(entry, nil, now)
	if _, _, fresh = cache.begin(key2, query, now); !fresh {
		t.Fatal("completed entry could not be evicted at capacity")
	}
	if len(cache.entries) != 1 {
		t.Fatal("cache exceeded entry limit")
	}
}

func TestPreparedAndDirectIngressShareReplayGuard(t *testing.T) {
	s, query, prepared := replayTestQuery(t, 5)
	if len(s.ingressReplay.entries) != 0 {
		t.Fatal("admission consumed replay state before dispatch")
	}
	first := s.handlePreparedIngress(query, prepared)
	second := s.handlePacket(query)
	if len(first) == 0 || !bytes.Equal(first, second) {
		t.Fatal("direct ingress did not reuse the prepared-ingress response")
	}
	if len(s.ingressReplay.entries) != 1 {
		t.Fatal("prepared ingress did not install its replay guard")
	}
}
