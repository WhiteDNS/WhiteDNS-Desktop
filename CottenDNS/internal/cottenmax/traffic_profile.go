package cottenmax

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	soar "cottendns-go/internal/cottenmax/engine"
)

const (
	TrafficProfileFull         = "full"
	TrafficProfileLow          = "low"
	DefaultLowReductionPercent = 35
	LowTrafficStreamsPerSecond = 2
	LowTrafficStreamBurst      = 4
	LowTrafficTransportBurst   = 2
)

// applyTrafficProfile runs before any socket is opened. A full client retains
// its original settings and never allocates a pacing object. All engines made
// by a low client receive the same limiter through the copied engine config.
func applyTrafficProfile(cfg *ClientConfig) (string, *soar.PercentagePacer, error) {
	profile := strings.ToLower(strings.TrimSpace(cfg.TrafficProfile))
	if profile == "" {
		profile = TrafficProfileFull
	}
	if profile != TrafficProfileFull && profile != TrafficProfileLow {
		return "", nil, fmt.Errorf("cottenmax: unknown traffic profile %q (want full or low)", cfg.TrafficProfile)
	}
	if cfg.LowReductionPercent == 0 {
		cfg.LowReductionPercent = DefaultLowReductionPercent
	}
	if cfg.LowReductionPercent < 10 || cfg.LowReductionPercent > 90 {
		return "", nil, fmt.Errorf("cottenmax: low reduction percent must be 10..90")
	}
	if profile == TrafficProfileFull {
		return profile, nil, nil
	}
	cfg.Discovery = lowTrafficDiscovery(cfg.Discovery)
	if original := cfg.DiscoveryForDomain; original != nil {
		cfg.DiscoveryForDomain = func(domain string) Discovery {
			return lowTrafficDiscovery(original(domain))
		}
	}
	return profile, soar.NewPercentagePacer(cfg.LowReductionPercent), nil
}

func profileCeiling(value, ceiling int) int {
	if value <= 0 || value > ceiling {
		return ceiling
	}
	return value
}

func lowTrafficDiscovery(d Discovery) Discovery {
	d.Want = profileCeiling(d.Want, 4)
	d.Concurrency = profileCeiling(d.Concurrency, 2)
	d.Pace = max(d.Pace, 250*time.Millisecond)
	d.SampleRanges = 0
	return d
}

// dialAdmission bounds attempts, rather than only successful connections, so a
// set of unreachable destinations or domain fallbacks cannot bypass pacing.
// Its close context cancels callers waiting with a context.Background().
type dialAdmission struct {
	limiter *soar.QueryRateLimiter
	ctx     context.Context
	cancel  context.CancelFunc
}

func newLowDialAdmission() *dialAdmission {
	return newDialAdmission(LowTrafficStreamsPerSecond, LowTrafficStreamBurst)
}

func newDialAdmission(rate, burst int) *dialAdmission {
	ctx, cancel := context.WithCancel(context.Background())
	return &dialAdmission{limiter: soar.NewQueryRateLimiter(float64(rate), burst), ctx: ctx, cancel: cancel}
}

func (a *dialAdmission) wrapDial(dial func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	if dial == nil {
		dial = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if err := a.wait(ctx); err != nil {
			return nil, err
		}
		return dial(ctx, network, address)
	}
}

func (a *dialAdmission) wait(ctx context.Context) error {
	if a == nil {
		return nil
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if a.ctx.Err() != nil {
			return net.ErrClosed
		}
		now := time.Now()
		ok, next := a.limiter.TryTake(now)
		if ok {
			if err := ctx.Err(); err != nil {
				return err
			}
			if a.ctx.Err() != nil {
				return net.ErrClosed
			}
			return nil
		}
		timer := time.NewTimer(time.Until(next))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-a.ctx.Done():
			timer.Stop()
			return net.ErrClosed
		case <-timer.C:
		}
	}
}
