// Package clientui provides the optional interactive terminal dashboard. It is
// deliberately isolated from the tunnel runtime: services and embedded callers
// continue to receive the original line-oriented logs.
package clientui

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/term"

	"cottendns-go/internal/client"
	"cottendns-go/internal/version"
)

const (
	maxLogLines     = 200
	logQueueCap     = 512
	maxLogLineBytes = 16 * 1024
)

type tickMsg time.Time
type logMsg string
type runDoneMsg struct{ err error }

type logWriter struct {
	mu      sync.Mutex
	pending string
	lines   chan string
}

func newLogWriter() *logWriter { return &logWriter{lines: make(chan string, logQueueCap)} }

func (w *logWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	w.pending += string(p)
	for {
		idx := strings.IndexByte(w.pending, '\n')
		if idx < 0 {
			break
		}
		line := strings.Clone(strings.TrimSuffix(w.pending[max(0, idx-maxLogLineBytes):idx], "\r"))
		w.pending = w.pending[idx+1:]
		select {
		case w.lines <- line:
		default:
			select {
			case <-w.lines:
			default:
			}
			select {
			case w.lines <- line:
			default:
			}
		}
	}
	if len(w.pending) > maxLogLineBytes {
		w.pending = strings.Clone(w.pending[len(w.pending)-maxLogLineBytes:])
	}
	w.mu.Unlock()
	return len(p), nil
}

type model struct {
	app       *client.Client
	ctx       context.Context
	cancel    context.CancelFunc
	runDone   <-chan runDoneMsg
	logWriter *logWriter
	logs      []string
	width     int
	height    int
	started   time.Time
	lastAt    time.Time
	lastTX    uint64
	lastRX    uint64
	upSpeed   float64
	downSpeed float64
	status    client.StatusSnapshot
	stopping  bool
	runErr    error
}

func (m model) Init() tea.Cmd {
	return tea.Batch(tickCmd(), waitLogCmd(m.ctx, m.logWriter.lines), waitRunDoneCmd(m.runDone))
}

func tickCmd() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func waitLogCmd(ctx context.Context, lines <-chan string) tea.Cmd {
	return func() tea.Msg {
		select {
		case line := <-lines:
			return logMsg(line)
		case <-ctx.Done():
			return nil
		}
	}
}

func waitRunDoneCmd(done <-chan runDoneMsg) tea.Cmd {
	return func() tea.Msg { return <-done }
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc", "ctrl+c":
			if !m.stopping {
				m.stopping = true
				m.cancel()
			}
		}
	case tickMsg:
		now := time.Time(msg)
		status := m.app.StatusSnapshot()
		elapsed := now.Sub(m.lastAt).Seconds()
		if elapsed > 0 {
			m.upSpeed, m.downSpeed = 0, 0
			if status.TXBytes >= m.lastTX {
				m.upSpeed = float64(status.TXBytes-m.lastTX) / elapsed
			}
			if status.RXBytes >= m.lastRX {
				m.downSpeed = float64(status.RXBytes-m.lastRX) / elapsed
			}
		}
		m.status, m.lastAt = status, now
		m.lastTX, m.lastRX = status.TXBytes, status.RXBytes
		return m, tickCmd()
	case logMsg:
		line := compactLogLine(string(msg))
		if line != "" {
			m.logs = append(m.logs, line)
			if len(m.logs) > maxLogLines {
				m.logs = append([]string(nil), m.logs[len(m.logs)-maxLogLines:]...)
			}
		}
		return m, waitLogCmd(m.ctx, m.logWriter.lines)
	case runDoneMsg:
		m.runErr = msg.err
		return m, tea.Quit
	}
	return m, nil
}

var (
	accent = lipgloss.Color("39")
	good   = lipgloss.Color("42")
	warn   = lipgloss.Color("214")
	muted  = lipgloss.Color("245")
	panel  = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("238")).Padding(0, 1)
	title  = lipgloss.NewStyle().Bold(true).Foreground(accent)
	label  = lipgloss.NewStyle().Foreground(muted)
	value  = lipgloss.NewStyle().Bold(true)
)

func (m model) View() string {
	if m.width <= 0 || m.height <= 0 {
		return ""
	}
	view := m.dashboardView()
	if m.width < 92 || lipgloss.Height(view) > m.height {
		view = m.compactView()
	}
	lines := strings.Split(view, "\n")
	if len(lines) > m.height {
		lines = append(lines[:m.height-1], lines[len(lines)-1])
	}
	for i := range lines {
		lines[i] = ansi.Truncate(lines[i], m.width, "")
	}
	return strings.Join(lines, "\n")
}

func (m model) compactView() string {
	phase := strings.ToUpper(m.status.Phase)
	if m.stopping {
		phase = "SHUTTING DOWN"
	}
	lines := []string{
		title.Render("CottenDNS") + " " + label.Render(version.GetVersion()),
		phase + "  " + formatDuration(time.Since(m.started)),
		sectionTitle("RESOLVERS") + fmt.Sprintf("  %d / %d active", m.status.ActiveResolvers, m.status.ConfiguredResolvers),
		familyPolicyLabel(m.status.FamilyMode),
		sectionTitle("TUNNEL") + "  " + m.status.Transport,
		fmt.Sprintf("MTU up %d / down %d | streams %d", m.status.UploadMTU, m.status.DownloadMTU, m.status.ActiveStreams),
		"Proxy " + m.status.ProxyAddress,
		sectionTitle("TRAFFIC"),
		"Up " + formatSpeed(m.upSpeed) + " | down " + formatSpeed(m.downSpeed),
		sectionTitle("HEALTH") + fmt.Sprintf("  loss %.1f%%", float64(m.status.LossPerMille)/10),
		fmt.Sprintf("Queues %d/%d/%d | drops rx %d tx %d", m.status.TXQueue, m.status.EncodedQueue, m.status.RXQueue, m.status.RXDrops, m.status.TXDrops),
	}
	if m.status.LocalDNSEnabled {
		lines = append(lines, "DNS "+m.status.LocalDNSAddress)
	}
	lines = append(lines, sectionTitle("ACTIVITY"))
	lines = append(lines, renderActivity(m.logs, max(0, min(12, m.height-len(lines)-1)), m.width)...)
	lines = append(lines, label.Render("q / esc: quit"))
	return strings.Join(lines, "\n")
}

func (m model) dashboardView() string {
	width := m.width
	if width < 42 {
		width = 42
	}
	inner := width - 4
	header := title.Render("CottenDNS")
	if inner >= 58 {
		header += "  " + label.Render("resilient DNS tunnel")
	}
	header += strings.Repeat(" ", max(1, inner-lipgloss.Width(header)-len(version.GetVersion())-2))
	header += label.Render(version.GetVersion())

	phaseColor := warn
	if m.status.Phase == "connected" {
		phaseColor = good
	}
	phase := lipgloss.NewStyle().Bold(true).Foreground(phaseColor).Render(strings.ToUpper(m.status.Phase))
	if m.stopping {
		phase = lipgloss.NewStyle().Bold(true).Foreground(warn).Render("SHUTTING DOWN")
	}
	statusLine := phase + "   " + label.Render("uptime ") + value.Render(formatDuration(time.Since(m.started)))
	if inner >= 68 {
		statusLine = phase + "   " + phaseProgress(m.status.Phase, max(10, min(28, inner/3))) + "   " + label.Render("uptime ") + value.Render(formatDuration(time.Since(m.started)))
	}

	left := strings.Join([]string{
		sectionTitle("RESOLVERS"),
		row("Policy", familyPolicyLabel(m.status.FamilyMode)),
		row("Configured", fmt.Sprintf("%d  [IPv4 %d / IPv6 %d]", m.status.ConfiguredResolvers, m.status.ConfiguredIPv4, m.status.ConfiguredIPv6)),
		row("Active", fmt.Sprintf("%d  [IPv4 %d / IPv6 %d]", m.status.ActiveResolvers, m.status.ActiveIPv4, m.status.ActiveIPv6)),
		"",
		sectionTitle("TUNNEL"),
		row("Transport", m.status.Transport),
		row("MTU", fmt.Sprintf("upload %d / download %d", m.status.UploadMTU, m.status.DownloadMTU)),
		row("Streams", fmt.Sprintf("%d active", m.status.ActiveStreams)),
		row("Proxy", m.status.ProxyAddress),
	}, "\n")
	if m.status.LocalDNSEnabled {
		left += "\n" + row("Local DNS", m.status.LocalDNSAddress)
	}

	right := strings.Join([]string{
		sectionTitle("TRAFFIC"),
		row("Upload", formatSpeed(m.upSpeed)+"  ("+formatBytes(m.status.TXBytes)+")"),
		row("Download", formatSpeed(m.downSpeed)+"  ("+formatBytes(m.status.RXBytes)+")"),
		row("Loss", fmt.Sprintf("%.1f%%", float64(m.status.LossPerMille)/10)),
		"",
		sectionTitle("HEALTH"),
		row("Queues", fmt.Sprintf("tx %d / wire %d / rx %d", m.status.TXQueue, m.status.EncodedQueue, m.status.RXQueue)),
		row("Drops", fmt.Sprintf("rx %d / tx %d", m.status.RXDrops, m.status.TXDrops)),
		row("Recoveries", fmt.Sprintf("%d", m.status.Recoveries)),
		row("Stream errors", fmt.Sprintf("dial %d / write %d", m.status.StreamDialFailures, m.status.StreamWriteFailures)),
	}, "\n")

	columnWidth := (inner - 3) / 2
	if width < 92 {
		columnWidth = inner - 2
		leftPanel := panel.Width(columnWidth).Render(left)
		rightPanel := panel.Width(columnWidth).Render(right)
		return m.finishView(header, statusLine, leftPanel+"\n"+rightPanel, inner)
	}
	leftPanel := panel.Width(columnWidth).Render(left)
	rightPanel := panel.Width(columnWidth).Render(right)
	columns := lipgloss.JoinHorizontal(lipgloss.Top, leftPanel, " ", rightPanel)
	return m.finishView(header, statusLine, columns, inner)
}

func (m model) finishView(header, statusLine, columns string, inner int) string {
	used := lipgloss.Height(header) + lipgloss.Height(statusLine) + lipgloss.Height(columns) + 7
	logRows := m.height - used
	if logRows < 3 {
		logRows = 3
	}
	if logRows > 12 {
		logRows = 12
	}
	activity := renderActivity(m.logs, logRows, inner-4)
	activityPanel := panel.Width(inner).Height(logRows + 1).Render(sectionTitle("ACTIVITY") + "\n" + strings.Join(activity, "\n"))
	footer := label.Render("q / esc: quit   •   configuration and file logs remain unchanged")
	return strings.Join([]string{header, statusLine, columns, activityPanel, footer}, "\n\n")
}

func row(name, text string) string {
	return label.Render(fmt.Sprintf("%-13s", name)) + value.Render(text)
}
func sectionTitle(text string) string {
	return lipgloss.NewStyle().Bold(true).Foreground(accent).Render(text)
}

func familyPolicyLabel(mode string) string {
	switch mode {
	case "auto":
		return "auto (IPv4 preferred, IPv6 fallback)"
	case "auto → ipv6 fallback":
		return mode + " (active)"
	default:
		return mode
	}
}

func phaseProgress(phase string, width int) string {
	percent := 5
	switch phase {
	case "discovering resolvers":
		percent = 35
	case "connecting":
		percent = 75
	case "connected":
		percent = 100
	case "recovering":
		percent = 55
	case "stopped":
		percent = 0
	}
	if width < 6 {
		return ""
	}
	filled := width * percent / 100
	bar := strings.Repeat("━", filled) + strings.Repeat("─", width-filled)
	style := lipgloss.NewStyle().Foreground(warn)
	if percent == 100 {
		style = lipgloss.NewStyle().Foreground(good)
	}
	return label.Render("[") + style.Render(bar) + label.Render("]")
}

func renderActivity(lines []string, count, width int) []string {
	plain := tailLines(lines, count, width)
	out := make([]string, len(plain))
	for i, line := range plain {
		upper := strings.ToUpper(line)
		switch {
		case strings.Contains(upper, "[ERROR]") || strings.Contains(upper, "FAILED"):
			out[i] = lipgloss.NewStyle().Foreground(lipgloss.Color("203")).Render(line)
		case strings.Contains(upper, "[WARN]") || strings.Contains(upper, "FALLBACK") || strings.Contains(upper, "RECOVER"):
			out[i] = lipgloss.NewStyle().Foreground(warn).Render(line)
		case strings.Contains(upper, "CONNECTED") || strings.Contains(upper, "READY") || strings.Contains(upper, "SUCCESS"):
			out[i] = lipgloss.NewStyle().Foreground(good).Render(line)
		default:
			out[i] = line
		}
	}
	return out
}

func tailLines(lines []string, count, width int) []string {
	if count <= 0 {
		return nil
	}
	start := max(0, len(lines)-count)
	out := make([]string, 0, count)
	for _, line := range lines[start:] {
		out = append(out, truncateRunes(line, width))
	}
	for len(out) < count {
		out = append(out, "")
	}
	return out
}

func truncateRunes(text string, width int) string {
	if width <= 0 {
		return ""
	}
	return ansi.Truncate(text, width, "?")
}

func compactLogLine(line string) string {
	line = stripANSI(strings.TrimSpace(line))
	// The dashboard renders these counters directly; repeating the legacy stats
	// reporter in Activity would recreate the scrolling wall it replaces.
	if strings.Contains(line, " queues ") && strings.Contains(line, " recoveries ") {
		return ""
	}
	if idx := strings.Index(line, "] "); idx >= 0 {
		// Drop the timestamp and repeated application name, retaining level+message.
		if next := strings.Index(line[idx+2:], "] "); next >= 0 {
			line = line[idx+2+next+2:]
		}
	}
	return strings.TrimSpace(line)
}

func stripANSI(text string) string { return ansi.Strip(text) }

func formatBytes(n uint64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.2f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.2f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.2f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

func formatSpeed(n float64) string {
	if n < 0 {
		n = 0
	}
	return formatBytes(uint64(n)) + "/s"
}

func formatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Round(time.Second)
	h := int(d / time.Hour)
	m := int(d/time.Minute) % 60
	s := int(d/time.Second) % 60
	if h > 0 {
		return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
	}
	return fmt.Sprintf("%02d:%02d", m, s)
}

// ShouldUse reports whether the selected mode should launch the dashboard.
func ShouldUse(mode string) bool {
	return shouldUse(
		mode,
		term.IsTerminal(os.Stdin.Fd()),
		term.IsTerminal(os.Stdout.Fd()),
	)
}

func shouldUse(mode string, stdinTerminal, stdoutTerminal bool) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "plain":
		return false
	default:
		// Bubble Tea requires a real input and output terminal. This guard also
		// applies to an explicit "tui" request so GUI wrappers using pipes can
		// never be trapped in an unusable dashboard.
		return stdinTerminal && stdoutTerminal
	}
}

// Run owns the terminal until the client exits. The logger is redirected only
// for the duration of the dashboard; its file writer continues normally.
func Run(parent context.Context, app *client.Client, intro func()) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	w := newLogWriter()
	log := app.Log()
	var previous io.Writer
	if log != nil {
		previous = log.SwapConsoleWriter(w)
		defer log.SwapConsoleWriter(previous)
	}
	done := make(chan runDoneMsg, 1)
	finished := make(chan struct{})
	// Cleanup must finish before restoring the console writer, including when
	// the terminal fails to initialize or the parent cancels Bubble Tea.
	go func() {
		defer close(finished)
		if intro != nil {
			intro()
		}
		done <- runDoneMsg{err: app.Run(ctx)}
	}()
	defer func() { cancel(); <-finished }()
	now := time.Now()
	m := model{
		app: app, ctx: ctx, cancel: cancel, runDone: done, logWriter: w,
		width: 100, height: 30, started: now, lastAt: now, status: app.StatusSnapshot(),
	}
	result, err := tea.NewProgram(m, tea.WithAltScreen(), tea.WithContext(parent)).Run()
	if err != nil {
		if parent.Err() != nil {
			return nil
		}
		return err
	}
	if final, ok := result.(model); ok {
		return final.runErr
	}
	return nil
}
