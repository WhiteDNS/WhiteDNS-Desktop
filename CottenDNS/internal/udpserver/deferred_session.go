// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================

package udpserver

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"cottendns-go/internal/logger"
)

type deferredSessionLane struct {
	sessionID uint16
	streamID  uint16
}

type deferredSessionTask struct {
	lane       deferredSessionLane
	generation uint64
	run        func(context.Context)
}

type deferredSessionRun struct{ cancel context.CancelFunc }

type deferredSessionWorker struct {
	jobs    chan deferredSessionTask
	pending atomic.Int32
}

type deferredSessionProcessor struct {
	wg                 sync.WaitGroup
	log                *logger.Logger
	workers            []deferredSessionWorker
	mu                 sync.Mutex
	laneWorker         map[deferredSessionLane]int
	lanePending        map[deferredSessionLane]int32
	laneGeneration     map[deferredSessionLane]uint64
	cancelled          map[deferredSessionLane]struct{}
	running            map[deferredSessionLane]*deferredSessionRun
	sessionPending     map[uint16]int32
	sessionPendingCap  int32
	sessionPressureLog throttledLogState
	backlogHighLog     throttledLogState
	nextWorker         int
}

func deriveDeferredSessionPendingCap(workerCount int, queueLimit int) int32 {
	if workerCount <= 0 {
		workerCount = 1
	}

	if queueLimit < 1 {
		queueLimit = 256
	}

	// Keep the per-session cap comfortably below the total queue budget, but
	// large enough that one busy session does not trip overflow logs long before
	// the processor itself is under real pressure.
	capGuess := min(max(queueLimit/2, 32), 1024)

	totalCapacity := workerCount * queueLimit
	if capGuess > totalCapacity {
		capGuess = totalCapacity
	}

	if capGuess < 8 {
		capGuess = 8
	}

	// Never exceed what the worker queues can actually hold.
	if capGuess > totalCapacity {
		capGuess = totalCapacity
	}

	return int32(capGuess)
}

func newDeferredSessionProcessor(workerCount int, queueLimit int, log *logger.Logger) *deferredSessionProcessor {
	if workerCount <= 0 {
		return nil
	}
	if workerCount > 64 {
		workerCount = 64
	}
	if queueLimit < 1 {
		queueLimit = 256
	}
	if queueLimit > 8192 {
		queueLimit = 8192
	}

	workers := make([]deferredSessionWorker, workerCount)
	for i := range workers {
		workers[i].jobs = make(chan deferredSessionTask, queueLimit)
	}

	return &deferredSessionProcessor{
		log:               log,
		workers:           workers,
		laneWorker:        make(map[deferredSessionLane]int, 128),
		lanePending:       make(map[deferredSessionLane]int32, 128),
		laneGeneration:    make(map[deferredSessionLane]uint64, 128),
		cancelled:         make(map[deferredSessionLane]struct{}, 128),
		running:           make(map[deferredSessionLane]*deferredSessionRun, 128),
		sessionPending:    make(map[uint16]int32, 64),
		sessionPendingCap: deriveDeferredSessionPendingCap(workerCount, queueLimit),
	}
}

func (p *deferredSessionProcessor) Start(ctx context.Context) {
	if p == nil {
		return
	}

	for idx := range p.workers {
		p.wg.Add(1)
		go func(idx int) { defer p.wg.Done(); p.runDeferredWorker(ctx, idx) }(idx)
	}
}

func (p *deferredSessionProcessor) wait() {
	if p != nil {
		p.wg.Wait()
	}
}

// snapshot reports queued/running work and total bounded capacity. It only
// reads atomics and channel lengths, so health polling cannot contend with the
// deferred-session scheduler.
func (p *deferredSessionProcessor) snapshot() (pending int, capacity int) {
	if p == nil {
		return 0, 0
	}
	for i := range p.workers {
		pending += int(p.workers[i].pending.Load())
		capacity += cap(p.workers[i].jobs) + 1 // one running task per worker
	}
	return pending, capacity
}

func (p *deferredSessionProcessor) Enqueue(lane deferredSessionLane, run func(context.Context)) bool {
	if p == nil || run == nil || len(p.workers) == 0 {
		return false
	}

	task := deferredSessionTask{
		lane: lane,
		run:  run,
	}

	p.mu.Lock()
	delete(p.cancelled, lane)
	task.generation = p.laneGeneration[lane]
	if !p.canAcceptSessionLocked(lane.sessionID) {
		p.mu.Unlock()
		return false
	}
	if workerIdx, ok := p.laneWorker[lane]; ok {
		ok = p.enqueueToExistingWorkerLocked(workerIdx, task)

		p.mu.Unlock()
		return ok
	}

	start := p.nextWorker
	workerIdx := p.selectLeastLoadedWorkerLocked(start)
	if workerIdx < 0 {
		p.mu.Unlock()
		return false
	}
	p.nextWorker = (workerIdx + 1) % len(p.workers)
	p.laneWorker[lane] = workerIdx
	ok := p.tryEnqueueLocked(workerIdx, task)
	if !ok {
		delete(p.laneWorker, lane)
	}
	p.mu.Unlock()
	return ok
}

func (p *deferredSessionProcessor) RemoveSession(sessionID uint16) {
	if p == nil {
		return
	}
	p.mu.Lock()
	for lane, running := range p.running {
		if lane.sessionID == sessionID {
			running.cancel()
			delete(p.running, lane)
		}
	}
	for lane := range p.laneWorker {
		if lane.sessionID == sessionID {
			p.cancelled[lane] = struct{}{}
			p.laneGeneration[lane]++
		}
	}
	p.compactQueuesLocked(func(lane deferredSessionLane) bool {
		return lane.sessionID == sessionID
	})
	for lane := range p.laneWorker {
		if lane.sessionID == sessionID {
			p.clearIdleLaneLocked(lane)
		}
	}
	p.mu.Unlock()
}

func (p *deferredSessionProcessor) RemoveLane(lane deferredSessionLane) {
	if p == nil || lane.sessionID == 0 {
		return
	}
	p.mu.Lock()
	if running, ok := p.running[lane]; ok {
		running.cancel()
		delete(p.running, lane)
	}
	p.laneGeneration[lane]++

	if _, ok := p.cancelled[lane]; !ok {
		p.cancelled[lane] = struct{}{}
	}

	p.compactQueuesLocked(func(candidate deferredSessionLane) bool {
		return candidate == lane
	})
	p.clearIdleLaneLocked(lane)

	p.mu.Unlock()
}

func (p *deferredSessionProcessor) FinalizeLane(lane deferredSessionLane) {
	if p == nil || lane.sessionID == 0 {
		return
	}
	p.mu.Lock()

	p.laneGeneration[lane]++
	if _, ok := p.cancelled[lane]; !ok {
		p.cancelled[lane] = struct{}{}
	}

	p.compactQueuesLocked(func(candidate deferredSessionLane) bool {
		return candidate == lane
	})
	p.clearIdleLaneLocked(lane)

	p.mu.Unlock()
}

func (p *deferredSessionProcessor) runDeferredWorker(ctx context.Context, workerIdx int) {
	worker := &p.workers[workerIdx]
	for {
		select {
		case <-ctx.Done():
			return
		case task, ok := <-worker.jobs:
			if !ok {
				return
			}
			func() {
				taskCtx, running := p.beginTaskContext(ctx, task.lane, task.generation)
				defer func() {
					running.cancel()
					worker.pending.Add(-1)
					p.finishLane(task.lane, running)
					if recovered := recover(); recovered != nil && p.log != nil {
						p.log.Debugf(
							"Deferred Session Worker Panic, Worker: %d, Session: %d, Stream: %d, Error: %v",
							workerIdx+1,
							task.lane.sessionID,
							task.lane.streamID,
							recovered,
						)
					}
				}()
				task.run(taskCtx)
			}()
		}
	}
}

func (p *deferredSessionProcessor) beginTaskContext(parent context.Context, lane deferredSessionLane, generation ...uint64) (context.Context, *deferredSessionRun) {
	taskCtx, cancel := context.WithCancel(parent)
	running := &deferredSessionRun{cancel: cancel}
	if p == nil {
		return taskCtx, running
	}

	p.mu.Lock()
	if _, cancelled := p.cancelled[lane]; cancelled {
		cancel()
		p.mu.Unlock()
		return taskCtx, running
	}
	if len(generation) > 0 && generation[0] != p.laneGeneration[lane] {
		cancel()
		p.mu.Unlock()
		return taskCtx, running
	}
	p.running[lane] = running
	p.mu.Unlock()
	return taskCtx, running
}

func (p *deferredSessionProcessor) enqueueToExistingWorkerLocked(workerIdx int, task deferredSessionTask) bool {
	worker := &p.workers[workerIdx]
	worker.pending.Add(1)
	p.lanePending[task.lane]++
	p.sessionPending[task.lane.sessionID]++
	select {
	case worker.jobs <- task:
		p.maybeLogPressureLocked(workerIdx, task.lane)
		return true
	default:
		worker.pending.Add(-1)
		p.decrementLanePendingLocked(task.lane)
		p.decrementSessionPendingLocked(task.lane.sessionID)
		return false
	}
}

func (p *deferredSessionProcessor) tryEnqueueLocked(workerIdx int, task deferredSessionTask) bool {
	worker := &p.workers[workerIdx]
	worker.pending.Add(1)
	p.lanePending[task.lane]++
	p.sessionPending[task.lane.sessionID]++
	select {
	case worker.jobs <- task:
		p.maybeLogPressureLocked(workerIdx, task.lane)
		return true
	default:
		worker.pending.Add(-1)
		p.decrementLanePendingLocked(task.lane)
		p.decrementSessionPendingLocked(task.lane.sessionID)
		return false
	}
}

func (p *deferredSessionProcessor) finishLane(lane deferredSessionLane, completed *deferredSessionRun) {
	if p == nil {
		return
	}
	p.mu.Lock()
	if running, ok := p.running[lane]; ok && running == completed {
		running.cancel()
		delete(p.running, lane)
	}
	p.decrementLanePendingLocked(lane)
	p.decrementSessionPendingLocked(lane.sessionID)
	p.mu.Unlock()
}

func (p *deferredSessionProcessor) compactQueuesLocked(drop func(deferredSessionLane) bool) int {
	totalDropped := 0
	for idx := range p.workers {
		totalDropped += p.compactWorkerLocked(idx, drop)
	}
	return totalDropped
}

func (p *deferredSessionProcessor) compactWorkerLocked(workerIdx int, drop func(deferredSessionLane) bool) int {
	worker := &p.workers[workerIdx]
	if len(worker.jobs) == 0 {
		return 0
	}

	dropped := 0
	queued := make([]deferredSessionTask, 0, len(worker.jobs))
	for {
		select {
		case task := <-worker.jobs:
			if p.shouldDropTaskLocked(task.lane, drop) {
				worker.pending.Add(-1)
				p.decrementLanePendingLocked(task.lane)
				p.decrementSessionPendingLocked(task.lane.sessionID)
				dropped++
				continue
			}
			queued = append(queued, task)
		default:
			for _, task := range queued {
				worker.jobs <- task
			}
			return dropped
		}
	}
}

// The mapping belongs to all queued and running tasks in a lane. Removing it
// after only one task finishes lets a retry move to another worker and execute
// concurrently with the original stream's remaining fragments.
func (p *deferredSessionProcessor) decrementLanePendingLocked(lane deferredSessionLane) {
	if pending := p.lanePending[lane]; pending > 1 {
		p.lanePending[lane] = pending - 1
		return
	}
	delete(p.lanePending, lane)
	p.clearIdleLaneLocked(lane)
}

func (p *deferredSessionProcessor) clearIdleLaneLocked(lane deferredSessionLane) {
	if p.lanePending[lane] != 0 {
		return
	}
	delete(p.laneWorker, lane)
	delete(p.laneGeneration, lane)
	delete(p.cancelled, lane)
}

func (p *deferredSessionProcessor) canAcceptSessionLocked(sessionID uint16) bool {
	if p == nil || sessionID == 0 {
		return true
	}
	return p.sessionPending[sessionID] < p.sessionPendingCap
}

func (p *deferredSessionProcessor) decrementSessionPendingLocked(sessionID uint16) {
	if p == nil || sessionID == 0 {
		return
	}
	if pending := p.sessionPending[sessionID]; pending > 1 {
		p.sessionPending[sessionID] = pending - 1
		return
	}
	delete(p.sessionPending, sessionID)
}

func (p *deferredSessionProcessor) maybeLogPressureLocked(workerIdx int, lane deferredSessionLane) {
	if p == nil || p.log == nil {
		return
	}
	workerPending := p.workers[workerIdx].pending.Load()
	sessionPending := p.sessionPending[lane.sessionID]
	if workerPending < 16 && sessionPending < p.sessionPendingCap {
		return
	}

	if !p.backlogHighLog.allow(fmt.Sprintf("worker:%d:session:%d", workerIdx, lane.sessionID), time.Now(), time.Second) {
		return
	}
}

func (p *deferredSessionProcessor) workerCount() int {
	if p == nil {
		return 0
	}
	return len(p.workers)
}

func (p *deferredSessionProcessor) queueLimit() int {
	if p == nil || len(p.workers) == 0 {
		return 0
	}
	return cap(p.workers[0].jobs)
}

func (p *deferredSessionProcessor) sessionCap() int32 {
	if p == nil {
		return 0
	}
	return p.sessionPendingCap
}

func (p *deferredSessionProcessor) shouldDropTaskLocked(lane deferredSessionLane, drop func(deferredSessionLane) bool) bool {
	if drop != nil && drop(lane) {
		return true
	}
	_, cancelled := p.cancelled[lane]
	return cancelled
}

func (p *deferredSessionProcessor) selectLeastLoadedWorkerLocked(start int) int {
	if len(p.workers) == 0 {
		return -1
	}

	bestIdx := -1
	bestPending := int32(0)
	for offset := range p.workers {
		idx := (start + offset) % len(p.workers)
		pending := p.workers[idx].pending.Load()
		if bestIdx < 0 || pending < bestPending {
			bestIdx = idx
			bestPending = pending
			if pending == 0 {
				break
			}
		}
	}
	return bestIdx
}
