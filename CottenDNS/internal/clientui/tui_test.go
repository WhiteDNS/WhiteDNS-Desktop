package clientui

import (
	"context"
	"github.com/charmbracelet/x/ansi"
	"strings"
	"testing"
	"time"

	"cottendns-go/internal/client"
)

func TestShouldUseRequiresRealTerminal(t *testing.T) {
	tests := []struct {
		name                string
		mode                string
		stdinTTY, stdoutTTY bool
		want                bool
	}{
		{name: "auto terminal", mode: "auto", stdinTTY: true, stdoutTTY: true, want: true},
		{name: "requested terminal", mode: "tui", stdinTTY: true, stdoutTTY: true, want: true},
		{name: "plain terminal", mode: "plain", stdinTTY: true, stdoutTTY: true, want: false},
		{name: "requested with stdin pipe", mode: "tui", stdoutTTY: true, want: false},
		{name: "requested with stdout pipe", mode: "tui", stdinTTY: true, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := shouldUse(test.mode, test.stdinTTY, test.stdoutTTY); got != test.want {
				t.Fatalf("shouldUse(%q, %t, %t) = %t, want %t", test.mode, test.stdinTTY, test.stdoutTTY, got, test.want)
			}
		})
	}
}

func TestDashboardRendersNarrowAndWideLayouts(t *testing.T) {
	for _, width := range []int{40, 80, 120} {
		m := model{
			width: width, height: 28, started: time.Now().Add(-time.Minute),
			status: client.StatusSnapshot{
				Phase: "connected", Transport: "UDP", FamilyMode: "auto",
				ConfiguredResolvers: 4, ConfiguredIPv4: 2, ConfiguredIPv6: 2,
				ActiveResolvers: 2, ActiveIPv4: 2, UploadMTU: 180, DownloadMTU: 1200,
			},
			logs: []string{"[INFO] listener ready", "[WARN] IPv6 fallback active"},
		}
		view := m.View()
		for _, want := range []string{"CottenDNS", "CONNECTED", "RESOLVERS", "ACTIVITY"} {
			if !strings.Contains(view, want) {
				t.Fatalf("width %d view missing %q", width, want)
			}
		}
	}
}

func TestPhaseProgressRepresentsConnectionState(t *testing.T) {
	connected := phaseProgress("connected", 10)
	starting := phaseProgress("starting", 10)
	if connected == starting || !strings.Contains(connected, "━━━━━━━━━━") {
		t.Fatalf("unexpected phase bars: connected=%q starting=%q", connected, starting)
	}
}

func TestCompactLogLineRemovesANSIMetadata(t *testing.T) {
	line := "2026/08/12 12:00:00 \x1b[36m[CottenDns Client]\x1b[0m \x1b[32m[INFO]\x1b[0m connected"
	got := compactLogLine(line)
	if strings.Contains(got, "\x1b") || !strings.Contains(got, "connected") {
		t.Fatalf("compact log = %q", got)
	}
}

func TestLogWriterKeepsWholeLines(t *testing.T) {
	w := newLogWriter()
	_, _ = w.Write([]byte("one"))
	_, _ = w.Write([]byte(" line\ntwo lines\n"))
	if got := <-w.lines; got != "one line" {
		t.Fatalf("first line = %q", got)
	}
	if got := <-w.lines; got != "two lines" {
		t.Fatalf("second line = %q", got)
	}
}

func TestDashboardFitsTerminalCellsAndRows(t *testing.T) {
	for _, size := range [][2]int{{1, 1}, {20, 8}, {40, 24}, {80, 28}, {120, 28}, {120, 40}} {
		m := model{width: size[0], height: size[1], started: time.Now(), status: client.StatusSnapshot{Phase: "connected"}, logs: []string{strings.Repeat("?", 100)}}
		lines := strings.Split(m.View(), "\n")
		if len(lines) > size[1] {
			t.Fatalf("%v: %d rows", size, len(lines))
		}
		for _, line := range lines {
			if ansi.StringWidth(line) > size[0] {
				t.Fatalf("%v: overflowing line %q", size, line)
			}
		}
	}
	for _, width := range []int{0, 1, 2, 3, 4, 9} {
		if ansi.StringWidth(truncateRunes("?????", width)) > width {
			t.Fatalf("wide Unicode exceeds %d cells", width)
		}
	}
}

func TestLogWaitStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { waitLogCmd(ctx, make(chan string))(); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("log command leaked after cancellation")
	}
}

func TestLogWriterBoundsUnterminatedLines(t *testing.T) {
	w := newLogWriter()
	w.Write([]byte(strings.Repeat("x", 2*maxLogLineBytes)))
	if len(w.pending) > maxLogLineBytes {
		t.Fatal("unbounded unterminated log line")
	}
	w.Write([]byte("\n"))
	if len(<-w.lines) > maxLogLineBytes {
		t.Fatal("unbounded queued log line")
	}
}
