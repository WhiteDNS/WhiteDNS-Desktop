package soar

import "time"

// querySizer compares long names with short canaries. Ordinary congestion must
// not permanently reduce an already working path to its minimum query budget.
type querySizer struct {
	safe, max, ok, ceiling, trial int
	alt, earned, failures         int
	base, large                   outcomes
	blocked, retry                time.Time
}
type nameSample struct {
	target   int
	baseline bool
}

func newQuerySizer(safe, max int) *querySizer {
	return &querySizer{safe: safe, max: max, ok: safe, ceiling: max + 1}
}
func (q *querySizer) reset() { q.base = outcomes{}; q.large = outcomes{} }
func (q *querySizer) next(now time.Time) (cap int, sample nameSample, probe bool) {
	q.alt++
	if q.trial == 0 && q.ok < q.max && q.earned >= 3 && !now.Before(q.blocked) {
		if q.ceiling <= q.max && !now.Before(q.retry) {
			q.ceiling = q.max + 1
			q.retry = now.Add(10 * time.Minute)
		}
		if q.ceiling > q.ok+1 {
			q.trial = q.max
			if q.ceiling <= q.max {
				q.trial = (q.ok + q.ceiling) / 2
			}
			q.reset()
		}
	}
	if q.trial > 0 {
		if q.alt%2 == 0 {
			return q.trial, nameSample{target: q.trial}, true
		}
		return q.safe, nameSample{target: q.trial, baseline: true}, false
	}
	if q.ok > q.safe {
		switch q.alt % 8 {
		case 0:
			return q.safe, nameSample{target: q.ok, baseline: true}, false
		case 1:
			return q.ok, nameSample{target: q.ok}, false
		}
	}
	return q.ok, nameSample{}, false
}
func (q *querySizer) outcome(sample nameSample, lost bool, now time.Time) {
	if !lost {
		q.earned = min(q.earned+1, 3)
	}
	if sample.target == 0 {
		return
	}
	if sample.target != q.trial && sample.target != q.ok {
		return
	}
	if sample.baseline {
		q.base.record(lost)
	} else {
		q.large.record(lost)
	}
	full := q.large.n >= 16 && q.base.n >= 16
	if blatant(&q.large, &q.base) || (full && worse(&q.large, &q.base)) {
		q.ceiling = min(q.ceiling, sample.target)
		if q.ok >= sample.target {
			q.ok = q.safe
		}
		q.trial = 0
		q.earned = 0
		q.reset()
		q.failures = min(q.failures+1, 8)
		delay := time.Second * time.Duration(1<<min(q.failures, 5))
		q.blocked = now.Add(delay)
		q.retry = now.Add(30 * time.Second * time.Duration(1<<min(q.failures-1, 4)))
		return
	}
	if full {
		if q.trial != 0 {
			q.ok = q.trial
			q.trial = 0
			q.earned = 0
		}
		q.reset()
	}
}
