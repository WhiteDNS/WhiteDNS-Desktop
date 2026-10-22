// WhiteDNS Soar engine: local SOCKS5 CONNECT, authenticated discovery and scan telemetry.
package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/getlantern/soar"
)

type options struct {
	Transport            string `json:"transport"`
	Discovery            bool   `json:"discovery"`
	Country              string `json:"country"`
	DiscoveryWant        int    `json:"discoveryWant"`
	DiscoveryConcurrency int    `json:"discoveryConcurrency"`
	DiscoveryPaceMs      int    `json:"discoveryPaceMs"`
	SafeQName            int    `json:"safeQName"`
	MaxQName             int    `json:"maxQName"`
	MaxAnswer            int    `json:"maxAnswer"`
	HoldMs               int    `json:"holdMs"`
	MaxInflight          int    `json:"maxInflight"`
	MaxPathWindow        int    `json:"maxPathWindow"`
	MaxStreams           int    `json:"maxStreams"`
	StreamWindowKiB      int    `json:"streamWindowKiB"`
	SendBufferKiB        int    `json:"sendBufferKiB"`
	SessionIdleSeconds   int    `json:"sessionIdleSeconds"`
	DialTimeoutSeconds   int    `json:"dialTimeoutSeconds"`
}

type config struct {
	Zone            string   `json:"zone"`
	PublicKey       string   `json:"server_public_key"`
	Listen          string   `json:"listen"`
	Username        string   `json:"username"`
	Password        string   `json:"password"`
	SystemResolvers []string `json:"system_resolvers"`
	Soar            options  `json:"soar"`
}

func defaults() config {
	return config{Listen: "127.0.0.1:10886", Soar: options{
		Transport: "auto", Discovery: true, Country: "IR", DiscoveryWant: 2,
		DiscoveryConcurrency: 2, DiscoveryPaceMs: 1000, SafeQName: 101, MaxQName: 253,
		MaxAnswer: 1232, HoldMs: 500, MaxInflight: 128, MaxPathWindow: 32, MaxStreams: 128,
		StreamWindowKiB: 256, SendBufferKiB: 64, SessionIdleSeconds: 90, DialTimeoutSeconds: 90,
	}}
}

func (c config) validate() error {
	if len(c.SystemResolvers) > 8 {
		return errors.New("at most eight network DNS servers are supported")
	}
	for _, resolver := range c.SystemResolvers {
		if _, ok := normalizedResolver(resolver); !ok {
			return errors.New("network DNS server must be an IP address")
		}
	}
	ip, port, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return errors.New("listen must be a loopback IP:port")
	}
	a, err := netip.ParseAddr(ip)
	if err != nil || !a.IsLoopback() || port == "" {
		return errors.New("SOCKS listener must use loopback, for example 127.0.0.1:10886")
	}
	if ap, err := netip.ParseAddrPort(c.Listen); err != nil || ap.Port() == 0 {
		return errors.New("listen port must be between 1 and 65535")
	}
	if c.Zone != strings.ToLower(c.Zone) || len(c.Zone) > 45 || !strings.Contains(c.Zone, ".") {
		return errors.New("use one lowercase ASCII tunnel domain, maximum 45 characters")
	}
	for _, label := range strings.Split(c.Zone, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return errors.New("invalid tunnel domain")
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return errors.New("tunnel domain must use ASCII letters, numbers, dots and hyphens")
			}
		}
	}
	key, err := base64.StdEncoding.DecodeString(c.PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return errors.New("server PUBLIC key must be a base64-encoded 32-byte Ed25519 key")
	}
	if (c.Username == "") != (c.Password == "") || len(c.Username) > 255 || len(c.Password) > 255 {
		return errors.New("SOCKS authentication needs both username and password, each at most 255 bytes")
	}
	o := c.Soar
	if o.Transport != "auto" && o.Transport != "on" && o.Transport != "only" && o.Transport != "off" {
		return errors.New("resolver transport must be auto, on, only or off")
	}
	if len(o.Country) != 0 && (len(o.Country) != 2 || o.Country[0] < 'A' || o.Country[0] > 'Z' || o.Country[1] < 'A' || o.Country[1] > 'Z') {
		return errors.New("country must be a two-letter code or blank")
	}
	for _, bound := range []struct{ value, low, high int }{
		{o.SafeQName, 101, 253}, {o.MaxQName, o.SafeQName, 253}, {o.MaxAnswer, 512, 1232},
		{o.HoldMs, 100, 1500}, {o.MaxInflight, 8, 1024}, {o.MaxPathWindow, 2, 128}, {o.MaxStreams, 8, 256},
		{o.StreamWindowKiB, 64, 1024}, {o.SendBufferKiB, 32, 1024}, {o.SessionIdleSeconds, 15, 110},
		{o.DialTimeoutSeconds, 5, 120}, {o.DiscoveryWant, 1, 32}, {o.DiscoveryConcurrency, 1, 16}, {o.DiscoveryPaceMs, 100, 5000},
	} {
		if bound.value < bound.low || bound.value > bound.high {
			return errors.New("a Soar advanced setting is outside its supported range; reset to the Balanced preset")
		}
	}
	return nil
}

func (c config) clientConfig(resolvers []string) soar.Config {
	key, _ := base64.StdEncoding.DecodeString(c.PublicKey)
	o := c.Soar
	initial, candidates := c.resolverPlan(resolvers)
	return soar.Config{
		Zone: c.Zone, ServerKey: key, Resolvers: initial, TCP: o.Transport,
		SafeQName: o.SafeQName, MaxQName: o.MaxQName, MaxAnswer: o.MaxAnswer,
		Hold: time.Duration(o.HoldMs) * time.Millisecond, MaxInflight: o.MaxInflight,
		MaxPathWindow: o.MaxPathWindow, MaxStreams: o.MaxStreams,
		StreamWindow: uint64(o.StreamWindowKiB) * 1024, SendBuffer: o.SendBufferKiB * 1024,
		SessionIdle: time.Duration(o.SessionIdleSeconds) * time.Second,
		Discovery: soar.Discovery{Enabled: o.Discovery, Country: o.Country, Candidates: candidates,
			Want: o.DiscoveryWant, Concurrency: o.DiscoveryConcurrency, Pace: time.Duration(o.DiscoveryPaceMs) * time.Millisecond},
	}
}

func loadResolvers(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("resolver file could not be opened")
	}
	defer f.Close()
	if stat, err := f.Stat(); err != nil || stat.Size() > 16<<20 {
		return nil, errors.New("resolver file exceeds the 16 MiB input limit")
	}
	var out []string
	seen := map[string]bool{}
	s := bufio.NewScanner(io.LimitReader(f, 16<<20))
	for s.Scan() {
		line := strings.TrimSpace(strings.SplitN(s.Text(), "#", 2)[0])
		if line == "" {
			continue
		}
		var addr string
		if ip, err := netip.ParseAddr(line); err == nil {
			addr = net.JoinHostPort(ip.String(), "53")
		} else if ap, err := netip.ParseAddrPort(line); err == nil && ap.Port() != 0 {
			addr = ap.String()
		} else {
			return nil, errors.New("resolver file must contain one IP or IP:port per line")
		}
		if !seen[addr] {
			seen[addr] = true
			out = append(out, addr)
		}
	}
	return out, s.Err()
}

type dialFunc func(context.Context, string, string) (net.Conn, error)

// startupHTTPS authenticates the server and verifies real HTTPS before exposing SOCKS.
func startupHTTPS(ctx context.Context, dial dialFunc, roots *x509.CertPool) error {
	transport := &http.Transport{DialContext: dial, DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, TLSHandshakeTimeout: 45 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/", nil)
	resp, err := client.Do(req)
	if err != nil {
		var certificateError *tls.CertificateVerificationError
		if errors.As(err, &certificateError) {
			return errors.New("startup HTTPS certificate verification failed; check system certificates and device clock")
		}
		var networkError net.Error
		if ctx.Err() != nil || errors.As(err, &networkError) && networkError.Timeout() {
			return errors.New("startup HTTPS timed out; try another resolver, discovery or the Conservative preset")
		}
		return errors.New("startup HTTPS stream failed; try another resolver or the Conservative preset, and check server outbound HTTPS")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return errors.New("startup HTTPS destination returned an unsuccessful status")
	}
	_, err = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	return err
}

type proxy struct {
	cfg      config
	dial     dialFunc
	upload   atomic.Int64
	download atomic.Int64
}

func (p *proxy) handle(ctx context.Context, local net.Conn) {
	defer local.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = local.Close()
		case <-done:
		}
	}()
	_ = local.SetDeadline(time.Now().Add(15 * time.Second))
	var hello [2]byte
	if _, err := io.ReadFull(local, hello[:]); err != nil || hello[0] != 5 || hello[1] == 0 {
		return
	}
	methods := make([]byte, int(hello[1]))
	if _, err := io.ReadFull(local, methods); err != nil {
		return
	}
	want := byte(0)
	if p.cfg.Username != "" {
		want = 2
	}
	found := false
	for _, method := range methods {
		if method == want {
			found = true
		}
	}
	if !found {
		_, _ = local.Write([]byte{5, 255})
		return
	}
	if _, err := local.Write([]byte{5, want}); err != nil {
		return
	}
	if want == 2 {
		if _, err := io.ReadFull(local, hello[:]); err != nil || hello[0] != 1 || hello[1] == 0 {
			return
		}
		username := make([]byte, int(hello[1]))
		if _, err := io.ReadFull(local, username); err != nil {
			return
		}
		var size [1]byte
		if _, err := io.ReadFull(local, size[:]); err != nil || size[0] == 0 {
			return
		}
		password := make([]byte, int(size[0]))
		if _, err := io.ReadFull(local, password); err != nil {
			return
		}
		if !hmac.Equal(username, []byte(p.cfg.Username)) || !hmac.Equal(password, []byte(p.cfg.Password)) {
			_, _ = local.Write([]byte{1, 1})
			return
		}
		if _, err := local.Write([]byte{1, 0}); err != nil {
			return
		}
	}
	var header [4]byte
	if _, err := io.ReadFull(local, header[:]); err != nil || header[0] != 5 || header[2] != 0 {
		return
	}
	reply := func(code byte) { _, _ = local.Write([]byte{5, code, 0, 1, 127, 0, 0, 1, 0, 0}) }
	if header[1] != 1 {
		reply(7)
		return
	} // BIND and UDP ASSOCIATE are unsupported.
	var host string
	switch header[3] {
	case 1, 4:
		size := 4
		if header[3] == 4 {
			size = 16
		}
		raw := make([]byte, size)
		if _, err := io.ReadFull(local, raw); err != nil {
			return
		}
		host = net.IP(raw).String()
	case 3:
		var size [1]byte
		if _, err := io.ReadFull(local, size[:]); err != nil || size[0] == 0 {
			return
		}
		raw := make([]byte, int(size[0]))
		if _, err := io.ReadFull(local, raw); err != nil {
			return
		}
		host = string(raw)
		if strings.ContainsAny(host, "\x00\r\n") {
			reply(8)
			return
		}
	default:
		reply(8)
		return
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(local, portBytes[:]); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBytes[:])
	if port == 0 {
		reply(2)
		return
	}
	// The negotiation deadline must not shorten a slow authenticated tunnel dial.
	_ = local.SetDeadline(time.Time{})
	dialCtx, cancel := context.WithTimeout(ctx, time.Duration(p.cfg.Soar.DialTimeoutSeconds)*time.Second)
	remote, err := p.dial(dialCtx, "tcp", net.JoinHostPort(host, fmt.Sprint(port)))
	cancel()
	if err != nil {
		reply(5)
		return
	}
	defer remote.Close()
	go func() {
		select {
		case <-ctx.Done():
			_ = remote.Close()
		case <-done:
		}
	}()
	reply(0)
	_ = local.SetDeadline(time.Time{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := io.Copy(&countWriter{writer: remote, count: &p.upload}, local)
		if half, ok := remote.(interface{ CloseWrite() error }); ok {
			_ = half.CloseWrite()
		}
		if err != nil {
			_ = remote.Close()
			_ = local.Close()
		}
	}()
	_, err = io.Copy(&countWriter{writer: local, count: &p.download}, remote)
	if half, ok := local.(interface{ CloseWrite() error }); ok {
		_ = half.CloseWrite()
	}
	// If the origin ends its response while the app still holds its upload open,
	// close the app connection to avoid retaining the stream forever.
	_ = local.Close()
	if err != nil {
		_ = remote.Close()
	}
	wg.Wait()
}

type countWriter struct {
	writer io.Writer
	count  *atomic.Int64
}

func (w *countWriter) Write(data []byte) (int, error) {
	n, err := w.writer.Write(data)
	w.count.Add(int64(n))
	return n, err
}

func (p *proxy) serve(ctx context.Context, listener net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer listener.Close()
	go func() { <-ctx.Done(); _ = listener.Close() }()
	slots := make(chan struct{}, p.cfg.Soar.MaxStreams)
	var wg sync.WaitGroup
	defer func() { cancel(); wg.Wait() }()
	for {
		local, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case slots <- struct{}{}:
		default:
			_ = local.Close()
			continue
		}
		wg.Add(1)
		go func() { defer wg.Done(); defer func() { <-slots }(); p.handle(ctx, local) }()
	}
}

func telemetry(ctx context.Context, p *proxy, client *soar.Client) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var previousUp, previousDown int64
	ticks := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			up, down := p.upload.Load(), p.download.Load()
			fmt.Printf("WD_TRAFFIC %d B/s (Total: %d B) | %d B/s (Total: %d B)\n", up-previousUp, up, down-previousDown, down)
			previousUp, previousDown = up, down
			ticks++
			if ticks%5 == 0 {
				var detail []string
				for _, path := range client.PathStats() {
					if path.Verified && len(detail) < 4 {
						detail = append(detail, fmt.Sprintf("%s/%s rtt=%dms loss=%.0f%% qname=%d answer=%d window=%.1f suspended=%t", path.Resolver, path.Transport, path.RTT.Milliseconds(), path.Loss*100, path.NameLen, path.AnswerLimit, path.Window, path.Suspended))
					}
				}
				if len(detail) > 0 {
					fmt.Println("SOAR_PATHS " + strings.Join(detail, "; "))
				}
			}
			var active, valid []string
			for _, path := range client.PathStats() {
				if path.Verified && len(valid) < 64 {
					valid = append(valid, path.Resolver)
				}
				if path.Verified && !path.Suspended && len(active) < 64 {
					active = append(active, path.Resolver)
				}
			}
			list := func(values []string) string {
				if len(values) == 0 {
					return "-"
				}
				return strings.Join(values, ",")
			}
			fmt.Printf("WD_RESOLVERS active=%s standby=- valid=%s\n", list(active), list(valid))
		}
	}
}

func probeResolver(ctx context.Context, cfg config, resolver string, roots *x509.CertPool) bool {
	cfg.Soar.Discovery = false // Another resolver must never validate this candidate.
	client, err := soar.NewClient(cfg.clientConfig([]string{resolver}))
	if err != nil {
		return false
	}
	defer client.Close()
	return startupHTTPS(ctx, client.DialContext, roots) == nil
}

func scan(ctx context.Context, cfg config, resolvers []string) error {
	ctx, cancel := context.WithCancel(ctx)
	var completed, valid int
	var progressLock sync.Mutex
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				progressLock.Lock()
				fmt.Printf("WD_PROGRESS phase=probing completed=%d total=%d valid=%d rejected=%d percent=%d\n", completed, len(resolvers), valid, completed-valid, completed*100/max(len(resolvers), 1))
				progressLock.Unlock()
			}
		}
	}()
	defer func() { cancel(); <-heartbeatDone }()
	work := make(chan string)
	var wg sync.WaitGroup
	for range min(cfg.Soar.DiscoveryConcurrency, 8) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for resolver := range work {
				probeCtx, cancel := context.WithTimeout(ctx, time.Duration(min(cfg.Soar.DialTimeoutSeconds, 30))*time.Second)
				accepted := probeResolver(probeCtx, cfg, resolver, nil)
				cancel()
				event := "rejected"
				progressLock.Lock()
				if accepted {
					event = "valid"
					valid++
				}
				completed++
				fmt.Printf("WD_SCAN event=%s resolver=%s\n", event, resolver)
				fmt.Printf("WD_PROGRESS phase=probing completed=%d total=%d valid=%d rejected=%d percent=%d\n", completed, len(resolvers), valid, completed-valid, completed*100/max(len(resolvers), 1))
				progressLock.Unlock()
			}
		}()
	}
	for _, resolver := range resolvers {
		select {
		case work <- resolver:
		case <-ctx.Done():
			close(work)
			wg.Wait()
			return ctx.Err()
		}
	}
	close(work)
	wg.Wait()
	fmt.Printf("WD_SCAN event=complete total=%d valid=%d rejected=%d\n", len(resolvers), valid, len(resolvers)-valid)
	return nil
}

func run(ctx context.Context, args []string) error {
	ctx, stop := context.WithCancel(ctx)
	defer stop()
	fs := flag.NewFlagSet("whitedns-soar", flag.ContinueOnError)
	configFile := fs.String("config", "", "JSON engine configuration")
	resolverFile := fs.String("resolvers", "", "resolver list file")
	scanOnly := fs.Bool("scan-only", false, "validate each resolver with the Soar server key")
	version := fs.Bool("version", false, "print version")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *version {
		fmt.Println("WhiteDNS Soar engine 1.6.7; Soar v0.2.3 + WhiteDNS transport fixes")
		return nil
	}
	if *configFile == "" || *resolverFile == "" || fs.NArg() != 0 {
		return errors.New("-config and -resolvers are required")
	}
	f, err := os.Open(*configFile)
	if err != nil {
		return errors.New("engine configuration could not be opened")
	}
	cfg := defaults()
	decoder := json.NewDecoder(io.LimitReader(f, 65536))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&cfg)
	_ = f.Close()
	if err != nil {
		return errors.New("invalid Soar engine JSON configuration")
	}
	if err := cfg.validate(); err != nil {
		return err
	}
	resolvers, err := loadResolvers(*resolverFile)
	if err != nil {
		return err
	}
	if *scanOnly {
		return scan(ctx, cfg, resolvers)
	}
	if len(resolvers) == 0 && !cfg.Soar.Discovery {
		return errors.New("add resolvers or enable Soar discovery")
	}
	if len(resolvers) > 128 && !cfg.Soar.Discovery {
		return errors.New("use at most 128 runtime resolvers, or enable discovery for the remaining candidates")
	}
	if len(resolvers) > 8192 {
		return errors.New("runtime list is too large; scan it first and use the working resolvers")
	}
	fmt.Println("WD_PROGRESS phase=session percent=90")
	client, err := soar.NewClient(cfg.clientConfig(resolvers))
	if err != nil {
		return errors.New("Soar client configuration could not be started")
	}
	defer client.Close()
	p := &proxy{cfg: cfg, dial: client.DialContext}
	go telemetry(ctx, p, client)
	probeCtx, cancel := context.WithTimeout(ctx, time.Duration(cfg.Soar.DialTimeoutSeconds)*time.Second)
	err = startupHTTPS(probeCtx, client.DialContext, nil)
	cancel()
	if err != nil {
		if !client.Established() {
			return errors.New("no authenticated DNS tunnel; verify the public key and delegation, or enable discovery/change network resolvers")
		}
		return err
	}
	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return errors.New("local SOCKS port is unavailable; stop the other connection or choose another proxy port")
	}
	fmt.Println("SOAR_READY authenticated=1 https=1")
	fmt.Println("WD_PROGRESS phase=connected percent=100")
	return p.serve(ctx, listener)
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:]); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "SOAR_ERROR: "+err.Error())
		os.Exit(1)
	}
}
