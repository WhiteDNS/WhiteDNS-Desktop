package client

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cottendns-go/internal/logger"
)

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
