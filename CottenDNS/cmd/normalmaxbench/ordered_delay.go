package main

import (
	"container/heap"
	"context"
	"sync/atomic"
	"time"
)

type delayedWork struct {
	due      time.Time
	sequence uint64
	send     func()
}
type delayedHeap []delayedWork

func (q delayedHeap) Len() int { return len(q) }
func (q delayedHeap) Less(i, j int) bool {
	return q[i].due.Before(q[j].due) || q[i].due.Equal(q[j].due) && q[i].sequence < q[j].sequence
}
func (q delayedHeap) Swap(i, j int) { q[i], q[j] = q[j], q[i] }
func (q *delayedHeap) Push(v any)   { *q = append(*q, v.(delayedWork)) }
func (q *delayedHeap) Pop() any {
	old := *q
	n := len(old)
	v := old[n-1]
	old[n-1] = delayedWork{}
	*q = old[:n-1]
	return v
}

// One writer per direction preserves packet arrival order when the requested
// network has no reordering. One timer goroutine per packet would add arbitrary
// callback reordering to a burst and could spuriously trigger ARQ fast loss.
type orderedDelay struct {
	ctx      context.Context
	delay    time.Duration
	input    chan delayedWork
	done     chan struct{}
	sequence atomic.Uint64
}

func newOrderedDelay(ctx context.Context, delay time.Duration) *orderedDelay {
	d := &orderedDelay{ctx: ctx, delay: delay, input: make(chan delayedWork, 4096), done: make(chan struct{})}
	go d.run()
	return d
}
func (d *orderedDelay) schedule(send func()) {
	d.scheduleAt(time.Now().Add(d.delay), send)
}
func (d *orderedDelay) scheduleAt(due time.Time, send func()) {
	item := delayedWork{due: due, sequence: d.sequence.Add(1), send: send}
	select {
	case d.input <- item:
	case <-d.ctx.Done():
	}
}
func (d *orderedDelay) run() {
	defer close(d.done)
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	var q delayedHeap
	for {
		now := time.Now()
		for len(q) > 0 && !q[0].due.After(now) {
			item := heap.Pop(&q).(delayedWork)
			if d.ctx.Err() == nil {
				item.send()
			}
		}
		var wake <-chan time.Time
		if len(q) > 0 {
			timer.Reset(max(time.Until(q[0].due), 0))
			wake = timer.C
		} else {
			timer.Stop()
		}
		select {
		case <-d.ctx.Done():
			return
		case item := <-d.input:
			heap.Push(&q, item)
		case <-wake:
		}
	}
}
