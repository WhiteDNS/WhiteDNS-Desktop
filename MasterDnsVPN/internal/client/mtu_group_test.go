package client

import (
	"testing"
	"time"

	"masterdnsvpn-go/internal/arq"
	"masterdnsvpn-go/internal/config"
)

func TestEffectiveGroupUploadMTUUsesMinimumSelectedResolverMTU(t *testing.T) {
	c := &Client{}
	c.syncedUploadMTU = 80

	got := c.effectiveGroupUploadMTU([]Connection{
		{UploadMTUBytes: 140},
		{UploadMTUBytes: 120},
		{UploadMTUBytes: 138},
	})
	if got != 120 {
		t.Fatalf("expected group MTU 120, got %d", got)
	}

	fallback := c.effectiveGroupUploadMTU([]Connection{{}, {UploadMTUBytes: 0}})
	if fallback != 80 {
		t.Fatalf("expected fallback synced MTU 80, got %d", fallback)
	}
}

func TestNewStreamInitializesARQWithSelectedGroupMTU(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{
		ProtocolType:              "TCP",
		ResolverBalancingStrategy: BalancingLeastLoss,
		PacketDuplicationCount:    2,
		ARQWindowSize:             64,
	}, "a", "b", "c")
	c.syncedUploadMTU = 70
	setBalancerMTUActive(c.balancer, "a", 140)
	setBalancerMTUActive(c.balancer, "b", 138)
	setBalancerMTUActive(c.balancer, "c", 70)
	c.balancer.SeedResolverStats("a", 10, 0, 10*time.Millisecond, 10)
	c.balancer.SeedResolverStats("b", 10, 1, 10*time.Millisecond, 10)
	c.balancer.SeedResolverStats("c", 10, 2, 10*time.Millisecond, 10)

	stream := c.new_stream(77, nil, nil)
	arqObj, ok := stream.Stream.(*arq.ARQ)
	if !ok {
		t.Fatalf("expected ARQ stream, got %T", stream.Stream)
	}
	defer arqObj.Close("test complete", arq.CloseOptions{Force: true})

	if got := arqObj.MTU(); got != 138 {
		t.Fatalf("expected stream ARQ MTU from selected group minimum 138, got %d", got)
	}
}

func TestLeastLossMTURecheckChangeAffectsLaterDuplicateSelection(t *testing.T) {
	b := NewBalancer(BalancingLeastLoss, nil)
	b.SetConnections([]*Connection{
		{Key: "a"},
		{Key: "b"},
		{Key: "c"},
	})
	setBalancerMTUActive(b, "a", 140)
	setBalancerMTUActive(b, "b", 138)
	setBalancerMTUActive(b, "c", 70)
	b.SeedResolverStats("a", 10, 0, 10*time.Millisecond, 10)
	b.SeedResolverStats("b", 10, 1, 10*time.Millisecond, 10)
	b.SeedResolverStats("c", 10, 2, 10*time.Millisecond, 10)

	selected, err := b.SelectTargetsForPayload(0, 0, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(selected) != 2 || selected[0].Key != "a" || selected[1].Key != "b" {
		t.Fatalf("expected initial high-MTU group a,b, got %#v", selected)
	}

	_ = b.SetConnectionMTU("b", 70, 70, 300)
	_ = b.SetConnectionMTU("c", 136, 136, 300)
	selected, err = b.SelectTargetsForPayload(0, 0, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(selected) != 2 || selected[0].Key != "a" || selected[1].Key != "c" {
		t.Fatalf("expected rechecked MTUs to move selection to a,c, got %#v", selected)
	}
}
