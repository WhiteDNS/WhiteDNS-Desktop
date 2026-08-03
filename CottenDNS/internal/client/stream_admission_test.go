package client

import (
	"testing"
	"time"

	"cottendns-go/internal/config"
)

// admissibleClient builds a client that passes every admission gate: session
// ready, one valid resolver, no stall.
func admissibleClient(t *testing.T) *Client {
	t.Helper()
	c := buildTestClientWithResolvers(config.ClientConfig{
		StreamQueueInitialCapacity: 8,
		OrphanQueueInitialCapacity: 4,
	}, "resolver-a")
	c.sessionReady = true
	c.resetTunnelActivity(c.now())
	return c
}

func TestShouldAdmitNewLocalStreamHappyPath(t *testing.T) {
	c := admissibleClient(t)
	if ok, reason := c.shouldAdmitNewLocalStream(c.now()); !ok {
		t.Fatalf("expected admission, got refusal: %s", reason)
	}
}

// A transiently not-ready session (e.g. re-initializing after a blip) must NOT be
// refused: the stream is admitted and its SYN waits for the tunnel to return,
// rather than turning a brief reconnect into "connection refused".
func TestShouldAdmitNewLocalStreamAdmitsWhenSessionTransientlyNotReady(t *testing.T) {
	c := admissibleClient(t)
	c.sessionReady = false
	if ok, reason := c.shouldAdmitNewLocalStream(c.now()); !ok {
		t.Fatalf("transient not-ready must admit and queue, got refusal: %s", reason)
	}
}

// Likewise, a momentarily empty resolver pool mid-recovery must admit and queue,
// not refuse — as long as the tunnel is not persistently stalled.
func TestShouldAdmitNewLocalStreamAdmitsWhenResolversMomentarilyEmpty(t *testing.T) {
	c := admissibleClient(t)
	c.balancer.SetConnectionValidity("resolver-a", false)
	if ok, reason := c.shouldAdmitNewLocalStream(c.now()); !ok {
		t.Fatalf("momentarily empty pool must admit and queue, got refusal: %s", reason)
	}
}

// The hard concurrency cap is still enforced regardless of tunnel health.
func TestShouldAdmitNewLocalStreamRejectsAtStreamCap(t *testing.T) {
	c := admissibleClient(t)
	c.cfg.MaxActiveStreams = 1
	c.active_streams[1] = &Stream_client{StreamID: 1}
	if ok, _ := c.shouldAdmitNewLocalStream(c.now()); ok {
		t.Fatal("expected refusal at the active-stream cap")
	}
}

func TestShouldAdmitNewLocalStreamRejectsWhenTunnelStalled(t *testing.T) {
	c := admissibleClient(t)
	c.tunnelPacketTimeout = 4 * time.Second
	now := c.now()
	// A send with no response, older than the admission window, is a stall.
	window := c.streamAdmissionNoResponseWindow()
	c.lastTunnelSendUnix.Store(now.Add(-2 * window).UnixNano())
	c.lastTunnelResponseUnix.Store(now.Add(-3 * window).UnixNano())
	if ok, reason := c.shouldAdmitNewLocalStream(now); ok {
		t.Fatal("expected refusal when the tunnel is stalled")
	} else if reason == "" {
		t.Fatal("expected a non-empty stall reason")
	}
}

func TestRecordTunnelResponseClearsStall(t *testing.T) {
	c := admissibleClient(t)
	c.tunnelPacketTimeout = 4 * time.Second
	now := c.now()
	window := c.streamAdmissionNoResponseWindow()
	c.lastTunnelSendUnix.Store(now.Add(-2 * window).UnixNano())
	c.lastTunnelResponseUnix.Store(now.Add(-3 * window).UnixNano())
	if stalled, _ := c.tunnelResponseStalled(now); !stalled {
		t.Fatal("precondition: expected a stall")
	}
	// A fresh response must clear the stall immediately.
	c.recordTunnelResponse(now)
	if stalled, _ := c.tunnelResponseStalled(now); stalled {
		t.Fatal("recordTunnelResponse should clear the stall")
	}
}

// A transient loss must recover with lightweight session restarts; only a
// sustained streak of failures (no response in between) escalates to the full,
// expensive MTU re-probe.
func TestTransportRecoveryEscalatesOnlyAfterPersistentFailure(t *testing.T) {
	c := admissibleClient(t)
	c.sessionResetSignal = make(chan struct{}, 1)
	consumeRestart := func() {
		select {
		case <-c.sessionResetSignal:
		default:
		}
		c.runtimeResetPending.Store(false)
	}

	for i := 1; i < transportRecoveryEscalateThreshold; i++ {
		c.requestTransportRecovery("transient blip")
		if c.transportRecoveryPending.Load() {
			t.Fatalf("request %d must stay a lightweight restart, not a full re-probe", i)
		}
		consumeRestart()
	}

	c.requestTransportRecovery("persistent failure")
	if !c.transportRecoveryPending.Load() {
		t.Fatal("expected a full transport re-probe to arm after a persistent streak")
	}
	if got := c.transportRecoveryStreak.Load(); got != 0 {
		t.Fatalf("streak must reset when the heavy recovery arms, got %d", got)
	}
}

// A live tunnel response resets the streak, so an unrelated later blip starts
// fresh with a lightweight restart instead of counting toward escalation.
func TestTransportRecoveryStreakResetByTunnelResponse(t *testing.T) {
	c := admissibleClient(t)
	c.sessionResetSignal = make(chan struct{}, 1)
	consumeRestart := func() {
		select {
		case <-c.sessionResetSignal:
		default:
		}
		c.runtimeResetPending.Store(false)
	}

	for i := 1; i < transportRecoveryEscalateThreshold; i++ {
		c.requestTransportRecovery("blip")
		consumeRestart()
	}
	c.recordTunnelResponse(c.now())

	c.requestTransportRecovery("later unrelated blip")
	if c.transportRecoveryPending.Load() {
		t.Fatal("a tunnel response should reset the streak so the next blip stays lightweight")
	}
}
