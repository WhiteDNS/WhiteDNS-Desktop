package udpserver

import (
	"context"
	"testing"
	"time"
)

func TestDeferredSessionLaneRemainsSerialWithQueuedRetry(t *testing.T) {
	p := newDeferredSessionProcessor(2, 8, nil)
	ctx, cancel := context.WithCancel(context.Background())
	p.Start(ctx)
	defer func() { cancel(); p.wait() }()
	lane := deferredSessionLane{sessionID: 100, streamID: 1}
	firstStarted, firstRelease := make(chan struct{}), make(chan struct{})
	secondStarted, secondRelease := make(chan struct{}), make(chan struct{})
	thirdStarted := make(chan struct{})
	if !p.Enqueue(lane, func(ctx context.Context) {
		close(firstStarted)
		select {
		case <-firstRelease:
		case <-ctx.Done():
		}
	}) {
		t.Fatal("first task was rejected")
	}
	<-firstStarted
	if !p.Enqueue(lane, func(ctx context.Context) {
		close(secondStarted)
		select {
		case <-secondRelease:
		case <-ctx.Done():
		}
	}) {
		t.Fatal("second task was rejected")
	}
	close(firstRelease)
	<-secondStarted
	if !p.Enqueue(lane, func(context.Context) { close(thirdStarted) }) {
		t.Fatal("retry was rejected")
	}
	select {
	case <-thirdStarted:
		t.Fatal("retry ran concurrently with an earlier task from the same stream")
	case <-time.After(30 * time.Millisecond):
	}
	close(secondRelease)
	select {
	case <-thirdStarted:
	case <-time.After(time.Second):
		t.Fatal("retry did not run after the prior task completed")
	}
}

func TestDeferredSessionCancellationCannotReviveDequeuedWork(t *testing.T) {
	for _, action := range []string{"remove_lane", "remove_session", "finalize_lane"} {
		t.Run(action, func(t *testing.T) {
			p := newDeferredSessionProcessor(2, 8, nil)
			lane := deferredSessionLane{sessionID: 100, streamID: 1}
			if !p.Enqueue(lane, func(context.Context) {}) {
				t.Fatal("initial task was rejected")
			}
			worker := p.laneWorker[lane]
			// Reproduce the gap between a worker receiving a task and acquiring
			// the scheduler lock to create that task's cancellation context.
			old := <-p.workers[worker].jobs
			switch action {
			case "remove_lane":
				p.RemoveLane(lane)
			case "remove_session":
				p.RemoveSession(lane.sessionID)
			case "finalize_lane":
				p.FinalizeLane(lane)
			}
			if !p.Enqueue(lane, func(context.Context) {}) {
				t.Fatal("fresh retry was rejected")
			}
			if got := p.laneWorker[lane]; got != worker {
				t.Fatal("retry moved while old lane work was still unwinding")
			}
			fresh := <-p.workers[worker].jobs
			oldCtx, oldRun := p.beginTaskContext(context.Background(), old.lane, old.generation)
			if oldCtx.Err() == nil {
				t.Fatal("a fresh retry revived canceled dequeued work")
			}
			freshCtx, freshRun := p.beginTaskContext(context.Background(), fresh.lane, fresh.generation)
			if freshCtx.Err() != nil {
				t.Fatal("fresh retry inherited an older task's cancellation")
			}
			p.finishLane(lane, oldRun)
			if freshCtx.Err() != nil {
				t.Fatal("old task completion canceled a newer running task")
			}
			p.RemoveLane(lane)
			if freshCtx.Err() == nil {
				t.Fatal("removing the lane failed to cancel its current task")
			}
			p.finishLane(lane, freshRun)
			if len(p.laneWorker) != 0 || len(p.lanePending) != 0 || len(p.laneGeneration) != 0 || len(p.running) != 0 || len(p.sessionPending) != 0 {
				t.Fatal("completed lane retained scheduler state")
			}
		})
	}
}

func TestDeferredSessionCleanupDoesNotRetainHistoricalLanes(t *testing.T) {
	p := newDeferredSessionProcessor(2, 8, nil)
	for stream := uint16(1); stream < 1000; stream++ {
		lane := deferredSessionLane{sessionID: 100, streamID: stream}
		p.RemoveLane(lane)
		p.FinalizeLane(lane)
	}
	if len(p.laneWorker) != 0 || len(p.lanePending) != 0 || len(p.laneGeneration) != 0 || len(p.cancelled) != 0 {
		t.Fatal("cleanup retained historical stream lanes without pending work")
	}
}

func TestDeferredSessionRemoveSessionCancelsEveryRunningLane(t *testing.T) {
	p := newDeferredSessionProcessor(2, 8, nil)
	laneA := deferredSessionLane{sessionID: 100, streamID: 1}
	laneB := deferredSessionLane{sessionID: 100, streamID: 2}
	laneOther := deferredSessionLane{sessionID: 101, streamID: 1}
	ctxA, runA := p.beginTaskContext(context.Background(), laneA)
	ctxB, runB := p.beginTaskContext(context.Background(), laneB)
	ctxOther, runOther := p.beginTaskContext(context.Background(), laneOther)
	defer runA.cancel()
	defer runB.cancel()
	defer runOther.cancel()
	p.RemoveSession(100)
	if ctxA.Err() == nil || ctxB.Err() == nil {
		t.Fatal("session removal left one of its running streams alive")
	}
	if ctxOther.Err() != nil {
		t.Fatal("session removal canceled a different session")
	}
}
