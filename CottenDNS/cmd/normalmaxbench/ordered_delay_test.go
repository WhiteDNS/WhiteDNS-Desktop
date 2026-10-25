package main

import (
	"context"
	"testing"
	"time"
)

func TestOrderedDelayPreservesDueOrderAndCancels(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	d := newOrderedDelay(ctx, 0)
	defer func() { cancel(); <-d.done }()
	out := make(chan int, 4)
	now := time.Now()
	// Arrival into the work queue can be reversed by producer scheduling; the
	// actual network receive timestamps still define the intended order.
	d.scheduleAt(now.Add(30*time.Millisecond), func() { out <- 3 })
	d.scheduleAt(now.Add(10*time.Millisecond), func() { out <- 1 })
	d.scheduleAt(now.Add(20*time.Millisecond), func() { out <- 2 })
	for want := 1; want <= 3; want++ {
		select {
		case got := <-out:
			if got != want {
				t.Fatalf("order %d want%d", got, want)
			}
		case <-time.After(time.Second):
			t.Fatal("ordered delay stalled")
		}
	}
	d.scheduleAt(now.Add(time.Hour), func() { out <- 4 })
	cancel()
	<-d.done
	select {
	case <-out:
		t.Fatal("cancelled future packet was sent")
	default:
	}
}
