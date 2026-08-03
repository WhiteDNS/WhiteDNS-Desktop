package client

import (
	"context"
	"time"
)

const (
	genericUDPFrameQueueCapacity = 256
	genericUDPRetryMinDelay      = 250 * time.Millisecond
	genericUDPRetryMaxDelay      = 10 * time.Second
	genericUDPWriteStallTimeout  = 60 * time.Second
)

// enqueueLatestGenericUDPFrame is deliberately non-blocking. When the tunnel
// cannot drain a full burst queue, the oldest not-yet-written UDP datagram is
// less useful than the newest one. Replacing it prevents stale real-time UDP
// from blocking the SOCKS receive loop and, critically, the optimized DNS/53
// fallback handled by that same socket. This bounds latency, not throughput:
// the writer drains continuously whenever tunnel capacity is available.
func enqueueLatestGenericUDPFrame(queue chan []byte, frame []byte) {
	select {
	case queue <- frame:
		return
	default:
	}
	select {
	case <-queue:
	default:
	}
	select {
	case queue <- frame:
	default:
	}
}

func latestGenericUDPFrame(queue chan []byte, fallback []byte) []byte {
	latest := fallback
	for {
		select {
		case frame := <-queue:
			latest = frame
		default:
			return latest
		}
	}
}

func waitGenericUDPRetry(ctx context.Context, delay time.Duration) bool {
	if delay <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func nextGenericUDPRetryDelay(current time.Duration) time.Duration {
	next := current * 2
	if next > genericUDPRetryMaxDelay {
		return genericUDPRetryMaxDelay
	}
	return next
}
