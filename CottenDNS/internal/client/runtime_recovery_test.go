package client

import (
	"testing"
	"time"

	"cottendns-go/internal/config"
)

func TestRequestTransportRecoveryArmsFullRescanForExplicitTransport(t *testing.T) {
	c := &Client{
		cfg:                config.ClientConfig{ResolverTransport: "udp"},
		sessionResetSignal: make(chan struct{}, transportRecoveryEscalateThreshold),
		successMTUChecks:   true,
		connections:        []Connection{{Key: "a", IsValid: true, UploadMTUBytes: 100, DownloadMTUBytes: 1000}},
	}
	// Transient requests stay lightweight session restarts and must not wipe MTU
	// state; only a sustained streak escalates to the full re-probe.
	for i := 1; i < transportRecoveryEscalateThreshold; i++ {
		c.requestTransportRecovery("transient blip")
		if c.transportRecoveryPending.Load() {
			t.Fatalf("request %d must not arm a full rescan", i)
		}
		select {
		case <-c.sessionResetSignal:
		default:
		}
		c.clearRuntimeResetRequest()
	}
	c.requestTransportRecovery("persistent outage")
	if !c.transportRecoveryPending.Load() {
		t.Fatal("path recovery was not armed after a persistent streak")
	}
	select {
	case <-c.sessionResetSignal:
	default:
		t.Fatal("session restart was not requested")
	}
	if !c.activatePendingTransportRecovery() {
		t.Fatal("pending recovery was not activated")
	}
	if c.successMTUChecks {
		t.Fatal("MTU discovery must be repeated after a persistent path outage")
	}
}

func TestRequestTransportRecoveryIsRateLimited(t *testing.T) {
	now := time.Now()
	c := &Client{
		cfg:                config.ClientConfig{ResolverTransport: "auto"},
		nowFn:              func() time.Time { return now },
		sessionResetSignal: make(chan struct{}, transportRecoveryEscalateThreshold*2),
	}
	// Drive a full streak to arm exactly one fleet rescan.
	reachThreshold := func() {
		for i := 0; i < transportRecoveryEscalateThreshold; i++ {
			c.requestTransportRecovery("outage")
			c.clearRuntimeResetRequest()
		}
	}
	reachThreshold()
	c.transportRecoveryPending.Store(false)
	// A second streak inside the cooldown must not arm a second rescan.
	reachThreshold()
	if got := c.transportRecoveryCount.Load(); got != 1 {
		t.Fatalf("recovery count = %d, want one fleet rescan inside cooldown", got)
	}
}

func TestSharedDoHHTTPClientIsReused(t *testing.T) {
	c := &Client{cfg: config.ClientConfig{}}
	first := c.sharedDoHHTTPClient()
	second := c.sharedDoHHTTPClient()
	if first != second {
		t.Fatal("DoH clients must share the HTTP/2 connection pool")
	}
	c.closeSharedDoHHTTPClient()
	if third := c.sharedDoHHTTPClient(); third == first {
		t.Fatal("closing the shared pool must allow a clean replacement")
	}
	c.closeSharedDoHHTTPClient()
}

func TestRuntimeDNSReadBufferIsSizedForConfiguredMTU(t *testing.T) {
	if got := runtimeDNSReadBufferSize(4000); got != runtimeDNSReadBufferFloor {
		t.Fatalf("default MTU buffer = %d, want cache-friendly floor %d", got, runtimeDNSReadBufferFloor)
	}
	if got := runtimeDNSReadBufferSize(20000); got != 22048 {
		t.Fatalf("large MTU buffer = %d, want MTU plus framing slack", got)
	}
	if got := runtimeDNSReadBufferSize(65535); got != RuntimeUDPReadBufferSize {
		t.Fatalf("oversize buffer = %d, want DNS framing ceiling", got)
	}
}
