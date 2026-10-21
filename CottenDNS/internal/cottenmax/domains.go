package cottenmax

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	soar "cottendns-go/internal/cottenmax/engine"
)

const MaxFailoverDomains = 8

// normalizeFailoverDomains validates every domain before opening any sockets.
// Standbys must fit the engine's initial 101-character QNAME, just like the
// primary. No network probes or separate MTU scan precede a healthy primary.
func normalizeFailoverDomains(primary string, standbys []string, initialNameLengths ...int) ([]string, error) {
	initialNameLength := 101
	if len(initialNameLengths) > 0 {
		initialNameLength = initialNameLengths[0]
	}
	return normalizeFailoverDomainsShaped(primary, standbys, initialNameLength, 63, false)
}

func normalizeFailoverDomainsShaped(primary string, standbys []string, initialNameLength, labelLength int, jitter bool) ([]string, error) {
	if labelLength == 0 {
		labelLength = 63
	}
	if labelLength < 1 || labelLength > 63 {
		return nil, fmt.Errorf("cottenmax: invalid QNAME label length")
	}
	separators := (55 - 1) / labelLength
	if jitter {
		separators += 3
	}
	inputs := append([]string{primary}, standbys...)
	domains := make([]string, 0, min(len(inputs), MaxFailoverDomains))
	seen := make(map[string]bool, len(inputs))
	for _, input := range inputs {
		trimmed := strings.Trim(input, ". \t\r\n")
		if trimmed == "" {
			return nil, fmt.Errorf("cottenmax: empty tunnel domain")
		}
		// Check before Unicode case folding, which can turn some non-ASCII
		// codepoints into ASCII and incorrectly admit them as DNS labels.
		for i := range len(trimmed) {
			if trimmed[i] < '!' || trimmed[i] > '~' {
				return nil, fmt.Errorf("cottenmax: domain must be printable ASCII")
			}
		}
		domain := strings.ToLower(trimmed)
		if seen[domain] {
			continue
		}
		for _, label := range strings.Split(domain, ".") {
			if len(label) == 0 || len(label) > 63 {
				return nil, fmt.Errorf("cottenmax: invalid domain label")
			}
		}
		// A HELLO contains a two-byte version/header and 32-byte X25519
		// key, requiring 55 base32 characters before the zone suffix.
		if len(Zone(domain))+1+55+separators > initialNameLength {
			return nil, fmt.Errorf("cottenmax: domain leaves insufficient initial handshake capacity")
		}
		if len(domains) == MaxFailoverDomains {
			return nil, fmt.Errorf("cottenmax: at most %d failover domains are supported", MaxFailoverDomains)
		}
		seen[domain] = true
		domains = append(domains, domain)
	}
	return domains, nil
}

type domainOpening struct {
	ready  chan struct{}
	engine *soar.Client
	err    error
}

type domainClient struct {
	domain  string
	engine  *soar.Client
	opening *domainOpening
}

// domainFailover never moves an existing stream or replays application bytes.
// Each new dial tries the last successful domain first. Other domains are
// activated lazily after a failed/timed-out attempt, with the same server pin
// and shared credential. An unconfirmed stream retains OPEN/data pipelining.
type domainFailover struct {
	mu                 sync.Mutex
	domains            []domainClient
	preferred          int
	closed             bool
	after              time.Duration
	cfg                soar.Config
	discoveryForDomain func(string) Discovery
	ctx                context.Context
	cancel             context.CancelFunc
}

func newDomainFailover(domains []string, after time.Duration, cfg soar.Config, primary *soar.Client, discoveryForDomain func(string) Discovery) *domainFailover {
	if after <= 0 {
		after = 3 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	f := &domainFailover{after: after, cfg: cfg, ctx: ctx, cancel: cancel, discoveryForDomain: discoveryForDomain}
	for _, domain := range domains {
		f.domains = append(f.domains, domainClient{domain: domain})
	}
	f.domains[0].engine = primary
	return f
}

func (f *domainFailover) preferredEngine() *soar.Client {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.domains[f.preferred].engine
}

func (f *domainFailover) engineFor(ctx context.Context, index int) (*soar.Client, error) {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return nil, net.ErrClosed
	}
	slot := &f.domains[index]
	if slot.engine != nil {
		engine := slot.engine
		f.mu.Unlock()
		return engine, nil
	}
	if opening := slot.opening; opening != nil {
		f.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-f.ctx.Done():
			return nil, net.ErrClosed
		case <-opening.ready:
			return opening.engine, opening.err
		}
	}
	opening := &domainOpening{ready: make(chan struct{})}
	slot.opening = opening
	cfg := f.cfg
	domain := slot.domain
	cfg.Zone = Zone(domain)
	// Engine.NewClient uses a background context to open its packet socket.
	// Preserve the caller's timeout and Close cancellation during lazy setup.
	listen := cfg.ListenPacket
	cfg.ListenPacket = func(_ context.Context, network, address string) (net.PacketConn, error) {
		return listen(ctx, network, address)
	}
	f.mu.Unlock()
	if f.discoveryForDomain != nil {
		cfg.Discovery = f.discoveryForDomain(domain)
	}
	engine, err := soar.NewClient(cfg)
	f.mu.Lock()
	if f.closed {
		err = net.ErrClosed
	}
	if err == nil {
		f.domains[index].engine = engine
		opening.engine = engine
	}
	opening.err = err
	f.domains[index].opening = nil
	close(opening.ready)
	f.mu.Unlock()
	if err != nil && engine != nil {
		engine.Close()
	}
	return opening.engine, err
}

func (f *domainFailover) dial(ctx context.Context, signed string, confirmed bool) (net.Conn, error) {
	f.mu.Lock()
	first, count, closed := f.preferred, len(f.domains), f.closed
	f.mu.Unlock()
	if closed {
		return nil, net.ErrClosed
	}
	var failures []error
	for step := range count {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		index := (first + step) % count
		attempt, cancel := context.WithTimeout(ctx, f.after)
		stop := context.AfterFunc(f.ctx, cancel)
		engine, err := f.engineFor(attempt, index)
		var conn net.Conn
		if err == nil {
			conn, err = dialEngine(attempt, engine, signed, confirmed)
		}
		stop()
		cancel()
		if f.ctx.Err() != nil {
			if conn != nil {
				conn.Close()
			}
			return nil, net.ErrClosed
		}
		if err == nil {
			f.mu.Lock()
			f.preferred = index
			f.mu.Unlock()
			return conn, nil
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		failures = append(failures, fmt.Errorf("%s: %w", f.domains[index].domain, err))
	}
	return nil, fmt.Errorf("cottenmax: all tunnel domains failed: %w", errors.Join(failures...))
}

func (f *domainFailover) close() error {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return nil
	}
	f.closed = true
	f.cancel()
	engines := make([]*soar.Client, 0, len(f.domains))
	for _, domain := range f.domains {
		if domain.engine != nil {
			engines = append(engines, domain.engine)
		}
	}
	f.mu.Unlock()
	for _, engine := range engines {
		engine.Close()
	}
	return nil
}

func (f *domainFailover) authenticate(ctx context.Context) error {
	f.mu.Lock()
	first, count, closed := f.preferred, len(f.domains), f.closed
	f.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	var failures []error
	for step := range count {
		if err := ctx.Err(); err != nil {
			return err
		}
		index := (first + step) % count
		attempt, cancel := context.WithTimeout(ctx, f.after)
		stop := context.AfterFunc(f.ctx, cancel)
		engine, err := f.engineFor(attempt, index)
		if err == nil {
			err = engine.Authenticate(attempt)
		}
		stop()
		cancel()
		if f.ctx.Err() != nil {
			return net.ErrClosed
		}
		if err == nil {
			f.mu.Lock()
			f.preferred = index
			f.mu.Unlock()
			return nil
		}
		failures = append(failures, err)
	}
	return fmt.Errorf("cottenmax: no authenticated tunnel domain: %w", errors.Join(failures...))
}
