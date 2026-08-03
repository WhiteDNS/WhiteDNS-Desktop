// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================

package client

import (
	"testing"
	"time"
)

func TestResolverPacer_ThrottleAndRecover(t *testing.T) {
	p := newResolverPacer(true)
	now := time.Now()

	// Healthy resolver is never paced.
	if p.paced("r1", now) {
		t.Fatal("a never-throttled resolver must not be paced")
	}

	// One overload signal opens a cooldown window.
	p.throttle("r1", now)
	if !p.paced("r1", now.Add(time.Millisecond)) {
		t.Fatal("resolver should be paced immediately after a throttle")
	}
	// Window expires.
	if p.paced("r1", now.Add(pacerBaseInterval+time.Millisecond)) {
		t.Fatal("resolver should leave cooldown after the base interval")
	}

	// Repeated throttles grow the window (multiplicative backoff).
	p.throttle("r1", now)
	p.throttle("r1", now)
	if !p.paced("r1", now.Add(pacerBaseInterval+time.Millisecond)) {
		t.Fatal("backoff window should grow with repeated throttles")
	}

	// Enough successes fully un-pace the resolver (multiplicative recovery to zero).
	for i := 0; i < 1000; i++ {
		p.success("r1")
	}
	if p.paced("r1", now.Add(10*time.Second)) {
		t.Fatal("sustained success should fully un-pace the resolver")
	}
}

func TestResolverPacer_DisabledIsNoop(t *testing.T) {
	p := newResolverPacer(false)
	p.throttle("r1", time.Now())
	if p.paced("r1", time.Now()) {
		t.Fatal("disabled pacer must never pace")
	}
}

func TestOrderByPacing_MovesPacedToBack(t *testing.T) {
	c := &Client{pacer: newResolverPacer(true)}
	now := c.now()
	c.pacer.throttle("b", now) // b is cooling down

	in := []Connection{{Key: "a"}, {Key: "b"}, {Key: "c"}}
	out := c.orderByPacing(in)

	if len(out) != 3 {
		t.Fatalf("expected all 3 candidates retained, got %d", len(out))
	}
	// Paced resolver "b" must be last; "a" and "c" keep their relative order.
	if out[2].Key != "b" {
		t.Errorf("paced resolver should sink to the back, got order %s,%s,%s", out[0].Key, out[1].Key, out[2].Key)
	}
	if out[0].Key != "a" || out[1].Key != "c" {
		t.Errorf("ready resolvers should keep relative order, got %s,%s", out[0].Key, out[1].Key)
	}
}
