//go:build maxexperiment

// maxexperiment is a loopback DNS laboratory, never a production client.
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cottendns-go/internal/cottenmax"
	engine "cottendns-go/internal/cottenmax/engine"
	"cottendns-go/internal/dnsparser"
)

type options struct {
	TrafficProfile string  `json:"traffic_profile"`
	Cipher         string  `json:"cipher"`
	Strategy       string  `json:"strategy"`
	Direction      string  `json:"direction"`
	Scope          string  `json:"cap_scope"`
	Domains        int     `json:"domains"`
	Flows          int     `json:"flows"`
	Bytes          int     `json:"bytes_per_flow"`
	RTT            int     `json:"rtt_ms"`
	Loss           float64 `json:"loss"`
	QPS            int     `json:"qps"`
	Name           int     `json:"qname_cap"`
	Answer         int     `json:"answer_cap"`
	Inflight       int     `json:"inflight_total"`
	Seed           int64   `json:"seed"`
	Blocked        int     `json:"blocked_domain"`
}

type counters struct {
	queries   atomic.Int64
	answers   atomic.Int64
	upBytes   atomic.Int64
	downBytes atomic.Int64
	dropUp    atomic.Int64
	dropDown  atomic.Int64
	rateDrop  atomic.Int64
	byDomain  [8]atomic.Int64
}

type wireStats struct {
	Queries   int64   `json:"queries"`
	Answers   int64   `json:"answers"`
	UpBytes   int64   `json:"up_wire_bytes"`
	DownBytes int64   `json:"down_wire_bytes"`
	DropUp    int64   `json:"loss_dropped_up"`
	DropDown  int64   `json:"loss_dropped_down"`
	RateDrop  int64   `json:"rate_dropped"`
	ByDomain  []int64 `json:"queries_by_domain"`
}

func (c *counters) snapshot(n int) wireStats {
	s := wireStats{Queries: c.queries.Load(), Answers: c.answers.Load(), UpBytes: c.upBytes.Load(), DownBytes: c.downBytes.Load(), DropUp: c.dropUp.Load(), DropDown: c.dropDown.Load(), RateDrop: c.rateDrop.Load()}
	for i := 0; i < n; i++ {
		s.ByDomain = append(s.ByDomain, c.byDomain[i].Load())
	}
	return s
}

func subtract(a, b wireStats) wireStats {
	a.Queries -= b.Queries
	a.Answers -= b.Answers
	a.UpBytes -= b.UpBytes
	a.DownBytes -= b.DownBytes
	a.DropUp -= b.DropUp
	a.DropDown -= b.DropDown
	a.RateDrop -= b.RateDrop
	for i := range a.ByDomain {
		a.ByDomain[i] -= b.ByDomain[i]
	}
	return a
}

func lost(sequence uint64, seed int64, loss float64) bool {
	if loss <= 0 {
		return false
	}
	x := sequence + uint64(seed) + 0x9e3779b97f4a7c15
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9
	x = (x ^ (x >> 27)) * 0x94d049bb133111eb
	x ^= x >> 31
	return float64(x>>11)/float64(uint64(1)<<53) < loss
}

type bucket struct {
	tokens float64
	at     time.Time
}

func (b *bucket) take(qps int, now time.Time) bool {
	if qps == 0 {
		return true
	}
	const burst = 8.0
	if b.at.IsZero() {
		b.at = now
		b.tokens = burst
	}
	b.tokens = min(burst, b.tokens+now.Sub(b.at).Seconds()*float64(qps))
	b.at = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

type relay struct {
	ctx          context.Context
	front        *net.UDPConn
	server       *net.UDPAddr
	domains      []string
	opts         options
	counts       counters
	mu           sync.Mutex
	peers        map[string]*net.UDPConn
	upSequence   atomic.Uint64
	downSequence atomic.Uint64
	wg           sync.WaitGroup
}

func (r *relay) after(fn func()) {
	if r.opts.RTT == 0 {
		if r.ctx.Err() == nil {
			fn()
		}
		return
	}
	time.AfterFunc(time.Duration(r.opts.RTT)*time.Millisecond/2, func() {
		if r.ctx.Err() == nil {
			fn()
		}
	})
}

func (r *relay) peer(addr *net.UDPAddr) (*net.UDPConn, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ctx.Err() != nil {
		return nil, r.ctx.Err()
	}
	if p := r.peers[addr.String()]; p != nil {
		return p, nil
	}
	p, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	r.peers[addr.String()] = p
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		buf := make([]byte, 4096)
		for {
			n, _, e := p.ReadFromUDP(buf)
			if e != nil {
				return
			}
			r.counts.answers.Add(1)
			r.counts.downBytes.Add(int64(n))
			if lost(r.downSequence.Add(1), r.opts.Seed+7919, r.opts.Loss) {
				r.counts.dropDown.Add(1)
				continue
			}
			data := append([]byte(nil), buf[:n]...)
			r.after(func() { _, _ = r.front.WriteToUDP(data, addr) })
		}
	}()
	return p, nil
}

func (r *relay) run() {
	defer r.wg.Done()
	buf := make([]byte, 4096)
	buckets := make([]bucket, len(r.domains))
	for {
		n, addr, err := r.front.ReadFromUDP(buf)
		if err != nil {
			return
		}
		r.counts.queries.Add(1)
		r.counts.upBytes.Add(int64(n))
		q, e := dnsparser.ParseDNSRequestLite(buf[:n])
		if e != nil {
			continue
		}
		index := -1
		name := strings.ToLower(strings.TrimSuffix(q.FirstQuestion.Name, "."))
		for i, d := range r.domains {
			if strings.HasSuffix(name, "."+cottenmax.Zone(d)) {
				index = i
				break
			}
		}
		if index < 0 {
			continue
		}
		r.counts.byDomain[index].Add(1)
		if index == r.opts.Blocked {
			r.counts.dropUp.Add(1)
			continue
		}
		if lost(r.upSequence.Add(1), r.opts.Seed, r.opts.Loss) {
			r.counts.dropUp.Add(1)
			continue
		}
		bucketIndex := 0
		if r.opts.Scope == "domain" {
			bucketIndex = index
		}
		if !buckets[bucketIndex].take(r.opts.QPS, time.Now()) {
			r.counts.rateDrop.Add(1)
			continue
		}
		p, e := r.peer(addr)
		if e != nil {
			continue
		}
		data := append([]byte(nil), buf[:n]...)
		r.after(func() { _, _ = p.WriteToUDP(data, r.server) })
	}
}

func (r *relay) close() {
	r.front.Close()
	r.mu.Lock()
	for _, p := range r.peers {
		p.Close()
	}
	r.mu.Unlock()
	r.wg.Wait()
}

type result struct {
	Options        options                `json:"options"`
	GoVersion      string                 `json:"go_version"`
	OS             string                 `json:"os"`
	Arch           string                 `json:"arch"`
	CPUs           int                    `json:"cpus"`
	TagBytes       int                    `json:"tag_bytes"`
	AuthenticateMS float64                `json:"cold_auth_probe_ms"`
	WarmupMS       float64                `json:"all_domain_warmup_ms"`
	OpenMS         float64                `json:"stream_open_ms"`
	Seconds        float64                `json:"transfer_seconds"`
	GoodputMbps    float64                `json:"goodput_mbps"`
	VerifiedBytes  int                    `json:"verified_bytes"`
	PeakInflight   int                    `json:"sampled_peak_inflight"`
	Traffic        wireStats              `json:"traffic"`
	Domains        []cottenmax.DomainStat `json:"domain_stats"`
	Error          string                 `json:"error,omitempty"`
}

func experiment(o options) (res result) {
	res.Options = o
	res.GoVersion = runtime.Version()
	res.OS = runtime.GOOS
	res.Arch = runtime.GOARCH
	res.CPUs = runtime.NumCPU()
	if err := engine.SetExperimentCipher(o.Cipher); err != nil {
		res.Error = err.Error()
		return
	}
	_, res.TagBytes = engine.ExperimentCipherInfo()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	domains := make([]string, o.Domains)
	for i := range domains {
		domains[i] = fmt.Sprintf("%c.test", 'a'+i)
	}
	serverPC, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		res.Error = err.Error()
		return
	}
	defer serverPC.Close()
	front, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		res.Error = err.Error()
		return
	}
	front.SetReadBuffer(4 << 20)
	front.SetWriteBuffer(4 << 20)
	serverPC.SetReadBuffer(4 << 20)
	serverPC.SetWriteBuffer(4 << 20)
	r := &relay{ctx: ctx, front: front, server: serverPC.LocalAddr().(*net.UDPAddr), domains: domains, opts: o, peers: map[string]*net.UDPConn{}}
	r.wg.Add(1)
	go r.run()
	defer func() { cancel(); r.close() }()
	payloads := make(map[string][]byte)
	for i := 0; i < o.Flows; i++ {
		b := make([]byte, o.Bytes)
		rand.New(rand.NewSource(o.Seed + int64(i))).Read(b)
		payloads[fmt.Sprintf("bench-%d.local:443", i)] = b
	}
	secret := "benchmark-only-not-a-deployment-key"
	key, err := cottenmax.SharedIdentity(secret)
	if err != nil {
		res.Error = err.Error()
		return
	}
	srv, err := cottenmax.NewServer(ctx, cottenmax.ServerConfig{Domains: domains, Secret: secret, Key: key, MaxSessions: 64, MaxStreams: 32, Dial: func(_ context.Context, target string) (net.Conn, error) {
		data, ok := payloads[target]
		if !ok {
			return nil, fmt.Errorf("unexpected benchmark destination")
		}
		a, b := net.Pipe()
		go func() {
			defer b.Close()
			b.SetDeadline(time.Now().Add(110 * time.Second))
			var header [9]byte
			if _, e := io.ReadFull(b, header[:]); e != nil {
				return
			}
			if int(binary.BigEndian.Uint64(header[1:])) != len(data) {
				return
			}
			if header[0] == 'D' {
				_, _ = io.Copy(b, bytes.NewReader(data))
			} else {
				got := make([]byte, len(data))
				if _, e := io.ReadFull(b, got); e == nil && bytes.Equal(got, data) {
					_, _ = b.Write([]byte("OK"))
				}
			}
		}()
		return a, nil
	}})
	if err != nil {
		res.Error = err.Error()
		return
	}
	defer srv.Close()
	go func() {
		b := make([]byte, 4096)
		for {
			n, a, e := serverPC.ReadFromUDP(b)
			if e != nil {
				return
			}
			srv.DispatchUDP(b[:n], serverPC, a)
		}
	}()
	cli, err := cottenmax.NewClient(cottenmax.ClientConfig{TrafficProfile: o.TrafficProfile, Domain: domains[0], Domains: domains[1:], DomainStrategy: o.Strategy, Secret: secret, Resolvers: []string{front.LocalAddr().String()}, TCP: "off", MaxInflight: o.Inflight, MaxPathWindow: o.Inflight, SafeQName: o.Name, MaxQName: o.Name, MaxAnswer: o.Answer, Hold: 0, FailoverAfter: 2 * time.Second})
	if err != nil {
		res.Error = err.Error()
		return
	}
	defer cli.Close()
	start := time.Now()
	if err = cli.Authenticate(ctx); err == nil {
		err = cli.Probe(ctx, 32)
	}
	res.AuthenticateMS = float64(time.Since(start).Microseconds()) / 1000
	if err != nil {
		res.Error = "warmup: " + err.Error()
		return
	}
	// Warm every optional domain with an authenticated transfer, outside the timed payload.
	warmCount := 2
	if o.Strategy == "parallel" {
		warmCount *= o.Domains
	}
	for i := 1; i < warmCount; i++ {
		if err = cli.Probe(ctx, 32); err != nil {
			res.Error = "domain warmup: " + err.Error()
			return
		}
	}
	res.WarmupMS = float64(time.Since(start).Microseconds()) / 1000
	conns := make([]net.Conn, o.Flows)
	errs := make(chan error, o.Flows)
	var wg sync.WaitGroup
	start = time.Now()
	for i := range conns {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, e := cli.Dial(ctx, fmt.Sprintf("bench-%d.local:443", i))
			if e != nil {
				errs <- e
				return
			}
			conns[i] = c
			c.SetDeadline(time.Now().Add(100 * time.Second))
		}(i)
	}
	wg.Wait()
	close(errs)
	res.OpenMS = float64(time.Since(start).Microseconds()) / 1000
	defer func() {
		for _, c := range conns {
			if c != nil {
				c.Close()
			}
		}
	}()
	for e := range errs {
		if e != nil {
			res.Error = "stream open: " + e.Error()
			return
		}
	}
	before := r.counts.snapshot(o.Domains)
	stopSample := make(chan struct{})
	sampleDone := make(chan struct{})
	var peak atomic.Int64
	go func() {
		defer close(sampleDone)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopSample:
				return
			case <-ticker.C:
				inflight := 0
				for _, d := range cli.DomainStats() {
					for _, p := range d.Paths {
						inflight += p.Inflight
					}
				}
				for old := peak.Load(); int64(inflight) > old; old = peak.Load() {
					if peak.CompareAndSwap(old, int64(inflight)) {
						break
					}
				}
			}
		}
	}()
	start = time.Now()
	transferErrors := make(chan error, o.Flows)
	for i, c := range conns {
		wg.Add(1)
		go func(i int, c net.Conn) {
			defer wg.Done()
			data := payloads[fmt.Sprintf("bench-%d.local:443", i)]
			var h [9]byte
			h[0] = 'D'
			if o.Direction == "upload" {
				h[0] = 'U'
			}
			binary.BigEndian.PutUint64(h[1:], uint64(len(data)))
			if _, e := io.Copy(c, bytes.NewReader(h[:])); e != nil {
				transferErrors <- e
				return
			}
			if h[0] == 'D' {
				got := make([]byte, len(data))
				_, e := io.ReadFull(c, got)
				if e == nil && !bytes.Equal(got, data) {
					e = fmt.Errorf("corrupt download")
				}
				if e != nil {
					transferErrors <- e
				}
			}
			if h[0] == 'U' {
				_, e := io.Copy(c, bytes.NewReader(data))
				if e == nil {
					var ack [2]byte
					_, e = io.ReadFull(c, ack[:])
					if e == nil && string(ack[:]) != "OK" {
						e = fmt.Errorf("corrupt upload acknowledgement")
					}
				}
				if e != nil {
					transferErrors <- e
				}
			}
		}(i, c)
	}
	wg.Wait()
	res.Seconds = time.Since(start).Seconds()
	close(transferErrors)
	close(stopSample)
	<-sampleDone
	res.Traffic = subtract(r.counts.snapshot(o.Domains), before)
	res.Domains = cli.DomainStats()
	res.PeakInflight = int(peak.Load())
	for e := range transferErrors {
		if e != nil {
			res.Error = e.Error()
			return
		}
	}
	res.VerifiedBytes = o.Bytes * o.Flows
	res.GoodputMbps = float64(res.VerifiedBytes) * 8 / res.Seconds / 1e6
	return
}

func main() {
	var o options
	flag.StringVar(&o.TrafficProfile, "traffic-profile", "full", "full (existing unpaced behavior) or low (bounded query traffic)")
	flag.StringVar(&o.Cipher, "cipher", "chacha20-poly1305-8", "matched laboratory suite")
	flag.StringVar(&o.Strategy, "strategy", "failover", "failover or experimental parallel")
	flag.StringVar(&o.Direction, "direction", "download", "download or upload")
	flag.StringVar(&o.Scope, "cap-scope", "shared", "shared or domain recursive-resolver QPS cap")
	flag.IntVar(&o.Domains, "domains", 1, "configured equal-length domains")
	flag.IntVar(&o.Flows, "flows", 1, "simultaneous independent streams")
	flag.IntVar(&o.Bytes, "bytes", 65536, "verified random bytes per stream")
	flag.IntVar(&o.RTT, "rtt", 0, "added two-way DNS delay in milliseconds")
	flag.Float64Var(&o.Loss, "loss", 0, "independent request and response loss fraction")
	flag.IntVar(&o.QPS, "qps", 0, "recursive query limit (0 unlimited), burst 8")
	flag.IntVar(&o.Name, "qname", 101, "fixed DNS-name cap; no sizing-trial confound")
	flag.IntVar(&o.Answer, "answer", 512, "fixed DNS-answer cap")
	flag.IntVar(&o.Inflight, "inflight", 128, "global query budget")
	flag.Int64Var(&o.Seed, "seed", 1, "loss and payload seed")
	flag.IntVar(&o.Blocked, "blocked-domain", -1, "zero-based domain to blackhole, or -1")
	flag.Parse()
	if o.Domains < 1 || o.Domains > 8 || o.Flows < 1 || o.Flows > 32 || o.Bytes < 1 || o.Bytes > 16<<20 || o.Loss < 0 || o.Loss >= 1 || o.RTT < 0 || o.QPS < 0 || (o.Direction != "download" && o.Direction != "upload") || (o.Scope != "shared" && o.Scope != "domain") {
		fmt.Fprintln(os.Stderr, "invalid experiment options")
		os.Exit(2)
	}
	r := experiment(o)
	json.NewEncoder(os.Stdout).Encode(r)
	if r.Error != "" {
		os.Exit(1)
	}
}
