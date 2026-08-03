// ==============================================================================
// CottenDNS
// Tests for on-path DNS-injection hardening: a forged NXDOMAIN that races the
// real authoritative answer must NOT throttle or disable a working resolver
// (RESOLVER_IGNORE_INJECTED_NXDOMAIN). Genuine SERVFAIL/REFUSED still counts.
// ==============================================================================

package client

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"cottendns-go/internal/config"
	DnsParser "cottendns-go/internal/dnsparser"
	Enums "cottendns-go/internal/enums"
)

// buildRCodeResponse crafts a minimal, well-formed DNS response (a question, no
// answers) carrying the given transaction ID and RCODE — i.e. what an on-path
// injector or a genuinely failing resolver returns.
func buildRCodeResponse(t *testing.T, id uint16, rcode uint8) []byte {
	t.Helper()
	pkt, err := DnsParser.BuildTXTQuestionPacket("x.example.com", Enums.DNS_RECORD_TYPE_TXT, 0)
	if err != nil {
		t.Fatalf("BuildTXTQuestionPacket: %v", err)
	}
	binary.BigEndian.PutUint16(pkt[0:2], id)
	// QR=1, RD=1, plus the RCODE in the low nibble.
	binary.BigEndian.PutUint16(pkt[2:4], 0x8100|uint16(rcode&0x0F))
	return pkt
}

func resolverHealthEventCount(c *Client, key string) (int, time.Time) {
	c.resolverHealthMu.Lock()
	defer c.resolverHealthMu.Unlock()
	state := c.resolverHealth[key]
	if state == nil {
		return 0, time.Time{}
	}
	return len(state.Events), state.LastSuccessAt
}

func TestInjectedNXDOMAINDoesNotPenalizeResolver(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		ResolverIgnoreInjectedNXDOMAIN:  true,
		AutoDisableTimeoutServers:       true,
		AutoDisableTimeoutWindowSeconds: 3.0,
		TunnelPacketTimeoutSec:          10.0,
	}, "a", "b", "c", "d")
	c.initResolverRecheckMeta()

	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5300}
	const id uint16 = 4242
	sampleKey := resolverSampleKey{resolverAddr: addr.String(), dnsID: id}
	sentAt := time.Now()
	c.resolverPending[sampleKey] = resolverSample{serverKey: "a", sentAt: sentAt}

	// A forged NXDOMAIN races in before the real answer.
	c.handleInboundPacket(buildRCodeResponse(t, id, Enums.DNSR_CODE_NAME_ERROR), addr, "")

	if got := c.injectedNXDOMAINCount.Load(); got != 1 {
		t.Fatalf("expected 1 ignored injection, got %d", got)
	}
	// The pending sample must survive so the genuine answer can still be scored.
	c.resolverStatsMu.Lock()
	_, stillPending := c.resolverPending[sampleKey]
	c.resolverStatsMu.Unlock()
	if !stillPending {
		t.Fatal("forged NXDOMAIN consumed the pending query sample; the real answer would be lost")
	}
	// No failure must have been recorded against the resolver.
	if events, lastSuccess := resolverHealthEventCount(c, "a"); events != 0 || !lastSuccess.IsZero() {
		t.Fatalf("forged NXDOMAIN penalized resolver: events=%d lastSuccess=%v", events, lastSuccess)
	}

	// Now the genuine authoritative answer arrives with the same ID: it must
	// still be claimed as a success (proving the sample was preserved for it).
	realAnswer := make([]byte, 2)
	binary.BigEndian.PutUint16(realAnswer, id)
	c.trackResolverSuccess(realAnswer, addr, "", time.Now())

	c.resolverStatsMu.Lock()
	_, stillPendingAfter := c.resolverPending[sampleKey]
	c.resolverStatsMu.Unlock()
	if stillPendingAfter {
		t.Fatal("genuine answer did not consume the pending sample")
	}
	if _, lastSuccess := resolverHealthEventCount(c, "a"); lastSuccess.IsZero() {
		t.Fatal("genuine answer after a forged NXDOMAIN was not scored as success")
	}
}

func TestGenuineServfailStillCountsAsFailure(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		ResolverIgnoreInjectedNXDOMAIN:  true,
		AutoDisableTimeoutServers:       true,
		AutoDisableTimeoutWindowSeconds: 3.0,
		TunnelPacketTimeoutSec:          10.0,
	}, "a", "b", "c", "d")
	c.initResolverRecheckMeta()

	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5300}
	const id uint16 = 7
	sampleKey := resolverSampleKey{resolverAddr: addr.String(), dnsID: id}
	c.resolverPending[sampleKey] = resolverSample{serverKey: "a", sentAt: time.Now()}

	// SERVFAIL is a genuine overload signal, not injection — it must still count.
	c.handleInboundPacket(buildRCodeResponse(t, id, Enums.DNSR_CODE_SERVER_FAILURE), addr, "")

	if got := c.injectedNXDOMAINCount.Load(); got != 0 {
		t.Fatalf("SERVFAIL wrongly treated as injection: count=%d", got)
	}
	c.resolverStatsMu.Lock()
	_, stillPending := c.resolverPending[sampleKey]
	c.resolverStatsMu.Unlock()
	if stillPending {
		t.Fatal("SERVFAIL should consume the pending sample")
	}
	if events, _ := resolverHealthEventCount(c, "a"); events != 1 {
		t.Fatalf("expected 1 failure event from SERVFAIL, got %d", events)
	}
}

func TestNoDataResponseDoesNotClaimTunnelDelivery(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		AutoDisableTimeoutServers:       true,
		AutoDisableTimeoutWindowSeconds: 90.0,
		TunnelPacketTimeoutSec:          10.0,
	}, "a", "b", "c", "d")
	c.initResolverRecheckMeta()

	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5300}
	const id uint16 = 71
	key := resolverSampleKey{resolverAddr: addr.String(), dnsID: id}
	c.resolverPending[key] = resolverSample{serverKey: "a", sentAt: time.Now()}

	c.handleInboundPacket(buildRCodeResponse(t, id, 0), addr, "")

	c.resolverStatsMu.Lock()
	_, stillPending := c.resolverPending[key]
	c.resolverStatsMu.Unlock()
	if !stillPending {
		t.Fatal("NOERROR/NODATA response consumed a pending tunnel sample")
	}
	if events, lastSuccess := resolverHealthEventCount(c, "a"); events != 0 || !lastSuccess.IsZero() {
		t.Fatalf("NOERROR/NODATA was credited as tunnel delivery: events=%d lastSuccess=%v", events, lastSuccess)
	}
	if got := c.carrier.success[0].Load(); got != 0 {
		t.Fatalf("NOERROR/NODATA credited carrier success: got=%d", got)
	}
}

func TestDuplicateDecodedResponseCreditsCarrierOnce(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{}, "a")
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5300}
	const id uint16 = 72
	key := resolverSampleKey{resolverAddr: addr.String(), dnsID: id}
	c.resolverPending[key] = resolverSample{serverKey: "a", sentAt: time.Now()}
	packet := buildRCodeResponse(t, id, 0)

	c.trackResolverSuccess(packet, addr, "", time.Now())
	c.trackResolverSuccess(packet, addr, "", time.Now())

	if got := c.carrier.success[0].Load(); got != 1 {
		t.Fatalf("duplicate response carrier successes = %d, want 1", got)
	}
}

func TestInjectedNXDOMAINCountsAsFailureWhenToggleOff(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		ResolverIgnoreInjectedNXDOMAIN:  false, // legacy behavior
		AutoDisableTimeoutServers:       true,
		AutoDisableTimeoutWindowSeconds: 3.0,
		TunnelPacketTimeoutSec:          10.0,
	}, "a", "b", "c", "d")
	c.initResolverRecheckMeta()

	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5300}
	const id uint16 = 99
	sampleKey := resolverSampleKey{resolverAddr: addr.String(), dnsID: id}
	c.resolverPending[sampleKey] = resolverSample{serverKey: "a", sentAt: time.Now()}

	c.handleInboundPacket(buildRCodeResponse(t, id, Enums.DNSR_CODE_NAME_ERROR), addr, "")

	if got := c.injectedNXDOMAINCount.Load(); got != 0 {
		t.Fatalf("toggle off should not count injections, got %d", got)
	}
	if events, _ := resolverHealthEventCount(c, "a"); events != 1 {
		t.Fatalf("with toggle off, NXDOMAIN should record a failure event, got %d", events)
	}
}
