package client

import (
	"strings"
	"testing"
	"time"

	"stormdns-go/internal/config"
)

func newAdmissionTestClient(now time.Time) *Client {
	conn := &Connection{
		Domain:        "example.com",
		Resolver:      "127.0.0.1",
		ResolverPort:  53,
		ResolverLabel: "127.0.0.1:53",
		Key:           "127.0.0.1|53|example.com",
		IsValid:       true,
	}
	balancer := NewBalancer(BalancingRoundRobin)
	balancer.SetConnections([]*Connection{conn})

	c := &Client{
		balancer:            balancer,
		sessionReady:        true,
		tunnelPacketTimeout: 8 * time.Second,
	}
	c.nowFn = func() time.Time {
		return now
	}
	c.resetTunnelActivity(now)
	return c
}

func TestShouldAdmitNewLocalStreamAllowsFreshRuntime(t *testing.T) {
	now := time.Unix(100, 0)
	c := newAdmissionTestClient(now)

	ok, reason := c.shouldAdmitNewLocalStream(now.Add(time.Minute))
	if !ok {
		t.Fatalf("expected fresh runtime to admit streams, got reason %q", reason)
	}
}

func TestShouldAdmitNewLocalStreamRejectsStalledTunnel(t *testing.T) {
	now := time.Unix(100, 0)
	c := newAdmissionTestClient(now)
	c.recordTunnelResponse(now)
	c.recordTunnelSend(now.Add(time.Second))

	ok, reason := c.shouldAdmitNewLocalStream(now.Add(10 * time.Second))
	if ok {
		t.Fatal("expected stalled tunnel to reject new local streams")
	}
	if !strings.Contains(reason, "no tunnel response") {
		t.Fatalf("expected no-response reason, got %q", reason)
	}
}

func TestShouldAdmitNewLocalStreamRecoversAfterTunnelResponse(t *testing.T) {
	now := time.Unix(100, 0)
	c := newAdmissionTestClient(now)
	c.recordTunnelSend(now.Add(time.Second))
	c.recordTunnelResponse(now.Add(2 * time.Second))

	ok, reason := c.shouldAdmitNewLocalStream(now.Add(20 * time.Second))
	if !ok {
		t.Fatalf("expected response to close circuit, got reason %q", reason)
	}
}

func TestShouldAdmitNewLocalStreamRejectsWithoutResolvers(t *testing.T) {
	now := time.Unix(100, 0)
	c := &Client{
		balancer:            NewBalancer(BalancingRoundRobin),
		cfg:                 config.ClientConfig{},
		sessionReady:        true,
		tunnelPacketTimeout: 8 * time.Second,
	}
	c.resetTunnelActivity(now)

	ok, reason := c.shouldAdmitNewLocalStream(now)
	if ok {
		t.Fatal("expected no active resolvers to reject new local streams")
	}
	if !strings.Contains(reason, "no active resolvers") {
		t.Fatalf("expected resolver reason, got %q", reason)
	}
}

func TestShouldAdmitNewLocalStreamRejectsAtActiveStreamLimit(t *testing.T) {
	now := time.Unix(100, 0)
	c := newAdmissionTestClient(now)
	c.cfg.MaxActiveStreams = 1
	c.active_streams = map[uint16]*Stream_client{
		7: &Stream_client{StreamID: 7, Status: streamStatusActive},
	}

	ok, reason := c.shouldAdmitNewLocalStream(now)
	if ok {
		t.Fatal("expected active stream limit to reject new local streams")
	}
	if !strings.Contains(reason, "active stream limit") {
		t.Fatalf("expected active stream limit reason, got %q", reason)
	}
}
