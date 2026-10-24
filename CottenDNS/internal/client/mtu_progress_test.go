package client

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cottendns-go/internal/logger"
)

type maxStartupFixture struct {
	auth  func(context.Context) error
	probe func(context.Context, int) error
}

func (f maxStartupFixture) Authenticate(ctx context.Context) error { return f.auth(ctx) }
func (f maxStartupFixture) Probe(ctx context.Context, n int) error { return f.probe(ctx, n) }

// No application/proxy traffic is allowed to rescue startup here: Android's VPN
// is deliberately not established until the authenticated probe succeeds.
func TestCottenMaxStartupRetriesWithoutApplicationTraffic(t *testing.T) {
	for _, failedStage := range []string{"authenticating", "verifying"} {
		t.Run(failedStage, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "startup.log")
			log := logger.NewWithFile("test", "WARN", path)
			defer log.Close()
			c := &Client{log: log}
			c.runtimePhase.Store(clientPhaseConnecting)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			authCalls, probeCalls := 0, 0
			fixture := maxStartupFixture{
				auth: func(ctx context.Context) error {
					authCalls++
					if failedStage == "authenticating" && authCalls == 1 {
						return context.DeadlineExceeded
					}
					return nil
				},
				probe: func(ctx context.Context, n int) error {
					probeCalls++
					if n != 32 {
						t.Errorf("unexpected probe size %d", n)
					}
					if failedStage == "verifying" && probeCalls == 1 {
						return context.DeadlineExceeded
					}
					return nil
				},
			}
			c.runCottenMaxStartup(ctx, fixture)
			if ctx.Err() != nil || c.runtimePhase.Load() != clientPhaseConnected || authCalls != 2 {
				t.Fatalf("did not recover: phase=%d auth=%d probe=%d err=%v", c.runtimePhase.Load(), authCalls, probeCalls, ctx.Err())
			}
			out := readFile(t, path)
			for _, want := range []string{"phase=authenticating", "phase=verifying", "phase=retry", "stage=" + failedStage, "phase=connected percent=100"} {
				if !strings.Contains(out, want) {
					t.Errorf("missing %q in %s", want, out)
				}
			}
		})
	}
}

func TestCottenMaxStartupDoesNotReportReadyOnFailureAndCancelsRetry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "startup.log")
	log := logger.NewWithFile("test", "WARN", path)
	defer log.Close()
	c := &Client{log: log}
	c.runtimePhase.Store(clientPhaseConnecting)
	ctx, cancel := context.WithCancel(context.Background())
	failed := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.runCottenMaxStartup(ctx, maxStartupFixture{
			auth:  func(context.Context) error { close(failed); return errors.New("resolver unavailable") },
			probe: func(context.Context, int) error { return errors.New("unexpected probe") },
		})
	}()
	<-failed
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancellation did not stop the startup retry")
	}
	if c.runtimePhase.Load() == clientPhaseConnected || strings.Contains(readFile(t, path), "phase=connected") {
		t.Fatal("failed startup reported a usable tunnel")
	}
}

func TestCottenMaxStartupCancelsActiveStages(t *testing.T) {
	for _, stage := range []string{"authenticating", "verifying"} {
		t.Run(stage, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "startup.log")
			log := logger.NewWithFile("test", "WARN", path)
			defer log.Close()
			c := &Client{log: log}
			c.runtimePhase.Store(clientPhaseConnecting)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			started, done := make(chan struct{}), make(chan struct{})
			wait := func(ctx context.Context) error { close(started); <-ctx.Done(); return ctx.Err() }
			go func() {
				defer close(done)
				c.runCottenMaxStartup(ctx, maxStartupFixture{
					auth: func(ctx context.Context) error {
						if stage == "authenticating" {
							return wait(ctx)
						}
						return nil
					},
					probe: func(ctx context.Context, _ int) error { return wait(ctx) },
				})
			}()
			<-started
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("active startup stage ignored cancellation")
			}
			if c.runtimePhase.Load() == clientPhaseConnected || strings.Contains(readFile(t, path), "phase=connected") {
				t.Fatal("cancelled startup reported readiness")
			}
		})
	}
}

func TestCottenMaxStartupPreservesConfirmedProxyReadiness(t *testing.T) {
	path := filepath.Join(t.TempDir(), "startup.log")
	log := logger.NewWithFile("test", "WARN", path)
	defer log.Close()
	c := &Client{log: log}
	c.runtimePhase.Store(clientPhaseConnecting)
	c.runCottenMaxStartup(context.Background(), maxStartupFixture{
		auth: func(context.Context) error { return nil },
		probe: func(context.Context, int) error {
			c.runtimePhase.Store(clientPhaseConnected)
			return context.DeadlineExceeded
		},
	})
	if c.runtimePhase.Load() != clientPhaseConnected || strings.Contains(readFile(t, path), "phase=retry") {
		t.Fatal("diagnostic failure overwrote confirmed application readiness")
	}
}

// The desktop app draws its connection progress bar from WD_PROGRESS lines, so
// the MTU scan has to report as it goes. It must survive LOG_LEVEL=WARN, which
// suppresses the human-readable per-resolver lines.
func TestLogMTUProgressEmitsMachineLinesAtWarn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log.txt")
	log := logger.NewWithFile("test", "WARN", path)
	t.Cleanup(func() { _ = log.Close() })

	now := time.Now()
	c := &Client{log: log, nowFn: func() time.Time { return now }}
	c.resetMTUProgressThrottle()

	counters := &mtuScanCounters{}
	total := 4

	c.logMTUProgress(counters, total) // completed=0, always emitted
	for i := 0; i < total; i++ {
		counters.completed.Add(1)
		if i%2 == 0 {
			counters.valid.Add(1)
		} else {
			counters.rejectUpload.Add(1)
		}
		now = now.Add(mtuProgressInterval)
		c.logMTUProgress(counters, total)
	}

	out := readFile(t, path)
	for _, want := range []string{
		"WD_PROGRESS phase=mtu percent=10 completed=0 total=4",
		"WD_PROGRESS phase=mtu percent=27 completed=1 total=4 valid=1 rejected=0",
		"WD_PROGRESS phase=mtu percent=80 completed=4 total=4 valid=2 rejected=2",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

// The scan runs one probe per resolver-domain pair and they finish in bursts, so
// unthrottled reporting would flood the log. Repeats within the interval that do
// not move the percent are dropped, but the final line never is.
func TestLogMTUProgressThrottlesRepeats(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log.txt")
	log := logger.NewWithFile("test", "WARN", path)
	t.Cleanup(func() { _ = log.Close() })

	now := time.Now()
	c := &Client{log: log, nowFn: func() time.Time { return now }}
	c.resetMTUProgressThrottle()

	counters := &mtuScanCounters{}
	counters.completed.Store(1)
	total := 100

	c.logMTUProgress(counters, total)
	c.logMTUProgress(counters, total)
	c.logMTUProgress(counters, total)

	if got := strings.Count(readFile(t, path), "phase=mtu"); got != 1 {
		t.Fatalf("expected the repeats to be throttled to one line, got %d", got)
	}

	counters.completed.Store(int32(total))
	c.logMTUProgress(counters, total)
	if !strings.Contains(readFile(t, path), "completed=100 total=100") {
		t.Fatal("the final progress line must never be throttled away")
	}
}
