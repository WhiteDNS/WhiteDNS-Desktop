package client

import (
	"testing"

	"cottendns-go/internal/compression"
	"cottendns-go/internal/config"
	VpnProto "cottendns-go/internal/vpnproto"
)

func TestApplySessionAcceptSupportsLegacyPayload(t *testing.T) {
	verify := [4]byte{1, 2, 3, 4}
	policy := VpnProto.SessionAcceptClientPolicy{MaxPacketsPerBatch: 2}
	payload := VpnProto.EncodeSessionAccept(0x5a, 0x7b,
		compression.PackPair(compression.TypeLZ4, compression.TypeZLIB),
		verify, policy, true)
	c := &Client{}
	packet := VpnProto.Packet{Payload: payload, LegacySessionID: true}

	if !c.applySessionAccept(packet, []byte{mtuProbeRawResponse}, verify) {
		t.Fatal("legacy SESSION_ACCEPT was rejected")
	}
	if c.sessionID != 0x5a || c.sessionCookie != 0x7b {
		t.Fatalf("legacy session state mismatch: id=%x cookie=%x", c.sessionID, c.sessionCookie)
	}
	if got := c.serverPolicySnapshot(); got == nil || got.MaxPacketsPerBatch != 2 {
		t.Fatalf("legacy server policy was not decoded: %+v", got)
	}
}

func TestNewFastConnectUsesHighestMTUBalancer(t *testing.T) {
	fast := New(config.ClientConfig{FastConnect: true}, nil, nil)
	if fast.balancer.strategy != BalancingHighestMTU {
		t.Fatalf("Fast Connect balancer strategy=%d, want %d", fast.balancer.strategy, BalancingHighestMTU)
	}
}
