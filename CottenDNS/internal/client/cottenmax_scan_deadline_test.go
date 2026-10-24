package client

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCottenMaxScanTransferGetsFreshDeadline(t *testing.T) {
	const budget = 20 * time.Millisecond
	var authDeadline time.Time
	var authContext, transferContext context.Context
	probes := 0
	authenticated, transferred := qualifyCottenMaxScanPath(context.Background(), maxStartupFixture{
		auth: func(ctx context.Context) error {
			authContext = ctx
			authDeadline, _ = ctx.Deadline()
			// A successful handshake can become ready at the deadline. The
			// following transfer must not inherit that exhausted context.
			<-ctx.Done()
			return nil
		},
		probe: func(ctx context.Context, size int) error {
			probes++
			transferContext = ctx
			if size != 256 {
				t.Fatalf("unexpected optional sizing after authentication spent its budget: %d", size)
			}
			deadline, ok := ctx.Deadline()
			if !ok || !deadline.After(authDeadline) || ctx.Err() != nil {
				t.Fatalf("transfer inherited authentication deadline: deadline=%v auth=%v err=%v", deadline, authDeadline, ctx.Err())
			}
			return nil
		},
	}, budget)
	if !authenticated || !transferred || probes != 1 {
		t.Fatalf("usable slow path rejected: authenticated=%v transferred=%v probes=%d", authenticated, transferred, probes)
	}
	if authContext.Err() == nil || transferContext.Err() == nil {
		t.Fatal("stage contexts were not released")
	}
}

func TestCottenMaxScanOptionalSizingUsesRemainingBudget(t *testing.T) {
	var authDeadline time.Time
	probes := 0
	authenticated, transferred := qualifyCottenMaxScanPath(context.Background(), maxStartupFixture{
		auth: func(ctx context.Context) error {
			authDeadline, _ = ctx.Deadline()
			return nil
		},
		probe: func(ctx context.Context, size int) error {
			probes++
			if size == 256 {
				return nil
			}
			if size != 8192 {
				t.Fatalf("unexpected probe size %d", size)
			}
			deadline, ok := ctx.Deadline()
			if !ok || deadline.After(authDeadline) {
				t.Fatalf("optional sizing added another deadline: sizing=%v authentication=%v", deadline, authDeadline)
			}
			return context.DeadlineExceeded
		},
	}, time.Second)
	if !authenticated || !transferred || probes != 2 {
		t.Fatalf("optional sizing failure rejected a proven path: authenticated=%v transferred=%v probes=%d", authenticated, transferred, probes)
	}
}

func TestCottenMaxScanRejectsFailedStages(t *testing.T) {
	for _, stage := range []string{"authentication", "transfer"} {
		t.Run(stage, func(t *testing.T) {
			probes := 0
			authenticated, transferred := qualifyCottenMaxScanPath(context.Background(), maxStartupFixture{
				auth: func(context.Context) error {
					if stage == "authentication" {
						return errors.New("unreachable resolver")
					}
					return nil
				},
				probe: func(context.Context, int) error {
					probes++
					return errors.New("transfer failed")
				},
			}, time.Second)
			if transferred || authenticated != (stage == "transfer") || probes != map[string]int{"authentication": 0, "transfer": 1}[stage] {
				t.Fatalf("failed stage accepted: authenticated=%v transferred=%v probes=%d", authenticated, transferred, probes)
			}
		})
	}
}

func TestCottenMaxScanStagesRespectCancellation(t *testing.T) {
	for _, stage := range []string{"authentication", "transfer", "sizing"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			started, done := make(chan struct{}), make(chan struct{})
			var authenticated, transferred bool
			wait := func(ctx context.Context) error {
				close(started)
				<-ctx.Done()
				return ctx.Err()
			}
			go func() {
				defer close(done)
				authenticated, transferred = qualifyCottenMaxScanPath(ctx, maxStartupFixture{
					auth: func(ctx context.Context) error {
						if stage == "authentication" {
							return wait(ctx)
						}
						return nil
					},
					probe: func(ctx context.Context, size int) error {
						if size == 256 && stage == "sizing" {
							return nil
						}
						return wait(ctx)
					},
				}, time.Second)
			}()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("scan stage did not start")
			}
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("scan ignored parent cancellation")
			}
			if authenticated != (stage != "authentication") || transferred != (stage == "sizing") {
				t.Fatalf("incorrect proof after cancellation: authenticated=%v transferred=%v", authenticated, transferred)
			}
		})
	}
}
