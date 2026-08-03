package client

import (
	"context"
	"testing"
	"time"
)

func TestGenericUDPQueueKeepsNewestWithoutBlocking(t *testing.T) {
	queue := make(chan []byte, 2)
	enqueueLatestGenericUDPFrame(queue, []byte("oldest"))
	enqueueLatestGenericUDPFrame(queue, []byte("middle"))

	done := make(chan struct{})
	go func() {
		enqueueLatestGenericUDPFrame(queue, []byte("newest"))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("full generic UDP queue blocked the SOCKS receive path")
	}

	if got := string(<-queue); got != "middle" {
		t.Fatalf("first retained frame=%q want middle", got)
	}
	if got := string(<-queue); got != "newest" {
		t.Fatalf("second retained frame=%q want newest", got)
	}
}

func TestGenericUDPRetryWaitCancelsImmediately(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	if waitGenericUDPRetry(ctx, time.Minute) {
		t.Fatal("cancelled retry wait reported success")
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("cancelled retry wait took %s", elapsed)
	}
}

func TestGenericUDPRetryReplacesStalePendingFrame(t *testing.T) {
	queue := make(chan []byte, 4)
	queue <- []byte("newer")
	queue <- []byte("newest")
	if got := string(latestGenericUDPFrame(queue, []byte("stale"))); got != "newest" {
		t.Fatalf("retry frame=%q want newest", got)
	}
}
