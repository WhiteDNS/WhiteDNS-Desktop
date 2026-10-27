// normalmaxbench compares production Normal and Max clients through the same
// bounded, delayed UDP DNS path. It is a local-only measurement utility.
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
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cottendns-go/internal/dnsparser"
	"github.com/BurntSushi/toml"
)

type options struct {
	Mode           string  `json:"mode"`
	Direction      string  `json:"direction"`
	Flows          int     `json:"flows"`
	Bytes          int     `json:"bytes_per_flow"`
	RTT            int     `json:"rtt_ms"`
	Loss           float64 `json:"loss"`
	Name           int     `json:"qname_cap"`
	Answer         int     `json:"answer_cap"`
	Seed           int64   `json:"seed"`
	Timeout        int     `json:"timeout_seconds"`
	TunedMTU       bool    `json:"tuned_normal_minimum_mtu"`
	MinUploadMTU   int     `json:"normal_minimum_upload_mtu_override"`
	MinDownloadMTU int     `json:"normal_minimum_download_mtu_override"`
	NormalTemplate string  `json:"normal_config_template,omitempty"`
	NormalMethod   int     `json:"normal_encryption_method"`
	LowReduction   int     `json:"low_reduction_percent"`
	Client         string  `json:"client_binary"`
	Server         string  `json:"server_binary"`
	Output         string  `json:"runtime_dir"`
	RelayOrder     string  `json:"relay_order"`
}

type counts struct{ q, a, up, down, lossUp, lossDown, nameDrop, answerDrop atomic.Int64 }
type wire struct {
	Queries    int64 `json:"queries"`
	Answers    int64 `json:"answers"`
	UpBytes    int64 `json:"query_dns_bytes"`
	DownBytes  int64 `json:"answer_dns_bytes"`
	LossUp     int64 `json:"loss_dropped_queries"`
	LossDown   int64 `json:"loss_dropped_answers"`
	NameDrop   int64 `json:"oversize_name_drops"`
	AnswerDrop int64 `json:"oversize_answer_drops"`
}

func (c *counts) snapshot() wire {
	return wire{c.q.Load(), c.a.Load(), c.up.Load(), c.down.Load(), c.lossUp.Load(), c.lossDown.Load(), c.nameDrop.Load(), c.answerDrop.Load()}
}
func difference(a, b wire) wire {
	return wire{a.Queries - b.Queries, a.Answers - b.Answers, a.UpBytes - b.UpBytes, a.DownBytes - b.DownBytes, a.LossUp - b.LossUp, a.LossDown - b.LossDown, a.NameDrop - b.NameDrop, a.AnswerDrop - b.AnswerDrop}
}
func lost(seq uint64, seed int64, fraction float64) bool {
	x := seq + uint64(seed) + 0x9e3779b97f4a7c15
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9
	x = (x ^ (x >> 27)) * 0x94d049bb133111eb
	x ^= x >> 31
	return float64(x>>11)/float64(uint64(1)<<53) < fraction
}

type relay struct {
	ctx                context.Context
	front              *net.UDPConn
	backend            *net.UDPAddr
	opts               options
	c                  counts
	mu                 sync.Mutex
	peers              map[string]*net.UDPConn
	wg                 sync.WaitGroup
	seqUp, seqDown     atomic.Uint64
	upDelay, downDelay *orderedDelay
}

func (r *relay) later(up bool, fn func()) {
	if r.opts.RelayOrder == "ordered" {
		if up {
			r.upDelay.schedule(fn)
		} else {
			r.downDelay.schedule(fn)
		}
		return
	}
	time.AfterFunc(time.Duration(r.opts.RTT)*time.Millisecond/2, func() {
		if r.ctx.Err() == nil {
			fn()
		}
	})
}
func (r *relay) peer(a *net.UDPAddr) (*net.UDPConn, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ctx.Err() != nil {
		return nil, r.ctx.Err()
	}
	if p := r.peers[a.String()]; p != nil {
		return p, nil
	}
	p, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		return nil, e
	}
	_ = p.SetReadBuffer(4 << 20)
	_ = p.SetWriteBuffer(4 << 20)
	r.peers[a.String()] = p
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		b := make([]byte, 65535)
		for {
			n, _, e := p.ReadFromUDP(b)
			if e != nil {
				return
			}
			r.c.a.Add(1)
			r.c.down.Add(int64(n))
			if n > r.opts.Answer {
				r.c.answerDrop.Add(1)
				continue
			}
			if lost(r.seqDown.Add(1), r.opts.Seed+7919, r.opts.Loss) {
				r.c.lossDown.Add(1)
				continue
			}
			d := append([]byte(nil), b[:n]...)
			r.later(false, func() { _, _ = r.front.WriteToUDP(d, a) })
		}
	}()
	return p, nil
}
func (r *relay) run() {
	defer r.wg.Done()
	b := make([]byte, 65535)
	for {
		n, a, e := r.front.ReadFromUDP(b)
		if e != nil {
			return
		}
		r.c.q.Add(1)
		r.c.up.Add(int64(n))
		q, e := dnsparser.ParseDNSRequestLite(b[:n])
		if e != nil || !q.HasQuestion {
			continue
		}
		if len(strings.TrimSuffix(q.FirstQuestion.Name, ".")) > r.opts.Name {
			r.c.nameDrop.Add(1)
			continue
		}
		if lost(r.seqUp.Add(1), r.opts.Seed, r.opts.Loss) {
			r.c.lossUp.Add(1)
			continue
		}
		p, e := r.peer(a)
		if e != nil {
			continue
		}
		d := append([]byte(nil), b[:n]...)
		r.later(true, func() { _, _ = p.WriteToUDP(d, r.backend) })
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
	if r.upDelay != nil {
		<-r.upDelay.done
		<-r.downDelay.done
	}
}

type result struct {
	Options           options `json:"options"`
	Go                string  `json:"go_version"`
	OS                string  `json:"os"`
	Arch              string  `json:"arch"`
	ColdSeconds       float64 `json:"cold_start_seconds"`
	OpenSeconds       float64 `json:"stream_open_seconds"`
	Seconds           float64 `json:"transfer_seconds"`
	Mbps              float64 `json:"goodput_mbps"`
	Verified          int     `json:"verified_bytes"`
	ColdTraffic       wire    `json:"cold_traffic"`
	SetupTraffic      wire    `json:"setup_traffic"`
	Traffic           wire    `json:"traffic"`
	TargetConnections int64   `json:"target_connections_during_open"`
	TargetCPS         float64 `json:"target_connection_starts_per_second"`
	QueryPS           float64 `json:"query_starts_per_second"`
	Error             string  `json:"error,omitempty"`
}

func freePort(network string) (int, error) {
	if network == "udp" {
		c, e := net.ListenPacket("udp4", "127.0.0.1:0")
		if e != nil {
			return 0, e
		}
		p := c.LocalAddr().(*net.UDPAddr).Port
		c.Close()
		return p, nil
	}
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		return 0, e
	}
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return p, nil
}
func launch(ctx context.Context, bin, cfg, logPath string) (func(), error) {
	f, e := os.Create(logPath)
	if e != nil {
		return nil, e
	}
	c := exec.CommandContext(ctx, bin, "--config", cfg)
	c.Dir = filepath.Dir(cfg)
	c.Stdout = f
	c.Stderr = f
	if e = c.Start(); e != nil {
		f.Close()
		return nil, e
	}
	return func() { _ = c.Process.Kill(); _ = c.Wait(); _ = f.Close() }, nil
}
func waitReady(ctx context.Context, addr, logPath string) error {
	for {
		if data, readErr := os.ReadFile(logPath); readErr == nil {
			if bytes.Contains(data, []byte("No valid connections found after MTU testing")) {
				return fmt.Errorf("no compatible resolver after one complete MTU-discovery pass; see client.log")
			}
			if bytes.Contains(data, []byte("phase=connected percent=100")) {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}
func openForward(ctx context.Context, proxy, direction string, id, length int) (net.Conn, error) {
	c, e := (&net.Dialer{}).DialContext(ctx, "tcp4", proxy)
	if e != nil {
		return nil, e
	}
	ok := false
	defer func() {
		if !ok {
			c.Close()
		}
	}()
	if d, yes := ctx.Deadline(); yes {
		c.SetDeadline(d)
	}
	if _, e = c.Write(header(direction, id, length)); e != nil {
		return nil, e
	}
	var ready [2]byte
	if _, e = io.ReadFull(c, ready[:]); e != nil {
		return nil, e
	}
	if string(ready[:]) != "RD" {
		return nil, fmt.Errorf("forward target readiness mismatch")
	}
	ok = true
	return c, nil
}
func header(direction string, id int, length int) []byte {
	b := make([]byte, 13)
	b[0] = 'D'
	if direction == "upload" {
		b[0] = 'U'
	}
	binary.BigEndian.PutUint32(b[1:5], uint32(id))
	binary.BigEndian.PutUint64(b[5:], uint64(length))
	return b
}

func bench(o options) (r result) {
	r.Options = o
	r.Go = runtime.Version()
	r.OS = runtime.GOOS
	r.Arch = runtime.GOARCH
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(o.Timeout)*time.Second)
	defer cancel()
	fail := func(e error) result { r.Error = e.Error(); return r }
	if e := os.MkdirAll(o.Output, 0755); e != nil {
		return fail(e)
	}
	serverPort, e := freePort("udp")
	if e != nil {
		return fail(e)
	}
	clientPort, e := freePort("tcp")
	if e != nil {
		return fail(e)
	}
	target, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		return fail(e)
	}
	defer target.Close()
	payloads := make([][]byte, o.Flows)
	for i := range payloads {
		payloads[i] = make([]byte, o.Bytes)
		_, _ = rand.New(rand.NewSource(o.Seed + int64(i))).Read(payloads[i])
	}
	var accepted atomic.Int64
	go func() {
		for {
			c, e := target.Accept()
			if e != nil {
				return
			}
			accepted.Add(1)
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(time.Duration(o.Timeout) * time.Second))
				var h [13]byte
				if _, e := io.ReadFull(c, h[:]); e != nil {
					return
				}
				id := int(binary.BigEndian.Uint32(h[1:5]))
				n := int(binary.BigEndian.Uint64(h[5:]))
				if id >= len(payloads) || n < 0 || n > len(payloads[id]) {
					return
				}
				data := payloads[id][:n]
				if _, e := c.Write([]byte("RD")); e != nil {
					return
				}
				var goByte [1]byte
				if _, e := io.ReadFull(c, goByte[:]); e != nil || goByte[0] != 'G' {
					return
				}
				if h[0] == 'D' {
					if _, e := io.Copy(c, bytes.NewReader(data)); e != nil {
						return
					}
				} else {
					got := make([]byte, n)
					if _, e := io.ReadFull(c, got); e != nil || !bytes.Equal(got, data) {
						return
					}
				}
				_, _ = c.Write([]byte("OK"))
			}()
		}
	}()
	front, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		return fail(e)
	}
	front.SetReadBuffer(4 << 20)
	front.SetWriteBuffer(4 << 20)
	re := &relay{ctx: ctx, front: front, backend: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: serverPort}, opts: o, peers: map[string]*net.UDPConn{}}
	if o.RelayOrder == "ordered" {
		re.upDelay = newOrderedDelay(ctx, time.Duration(o.RTT)*time.Millisecond/2)
		re.downDelay = newOrderedDelay(ctx, time.Duration(o.RTT)*time.Millisecond/2)
	}
	re.wg.Add(1)
	go re.run()
	defer func() { cancel(); re.close() }()
	defer func() {
		if r.Error != "" && r.Seconds == 0 {
			r.ColdTraffic = re.c.snapshot()
		}
	}()
	preset := "default"
	if o.Mode == "normal-speed-aes128" || o.Mode == "normal-desktop" {
		preset = "speed"
	}
	method := 3
	if o.Mode == "normal-default-xor" || o.Mode == "normal-android" {
		method = 1
	}
	if o.Mode == "normal-desktop" {
		method = 5
	}
	if o.NormalMethod >= 0 {
		method = o.NormalMethod
	}
	o.NormalMethod = method
	r.Options = o
	key := "1234567890abcdef1234567890abcdef"
	serverCfg := fmt.Sprintf("CONFIG_PRESET = \"default\"\nPROTOCOL_TYPE = \"TCP\"\nFORWARD_IP = \"127.0.0.1\"\nFORWARD_PORT = %d\nUDP_HOST = \"127.0.0.1\"\nUDP_PORT = %d\nUDP_IPV6_ENABLED = false\nTCP_LISTENER_ENABLED = false\nTCP_IPV6_ENABLED = false\nDOMAIN = [\"a.test\"]\nMIN_VPN_LABEL_LENGTH = 1\nDATA_ENCRYPTION_METHOD = 5\nENCRYPTION_AUTO_DETECT = true\nENCRYPTION_KEY_FILE = \"encrypt_key.txt\"\nFEC_DOWNLOAD_ENABLED = false\nFEC_AUTO_ENABLED = false\nFEC_SUPER_ENABLED = false\nLOG_LEVEL = \"INFO\"\n", target.Addr().(*net.TCPAddr).Port, serverPort)
	tunnel := "legacy"
	profile := "full"
	if strings.HasPrefix(o.Mode, "max-") {
		tunnel = "cottenmax"
		if strings.HasPrefix(o.Mode, "max-low") {
			profile = "low"
		}
	}
	clientCfg := fmt.Sprintf("CONFIG_PRESET = %q\nTUNNEL_MODE = %q\nCOTTENMAX_TRAFFIC_PROFILE = %q\nPROTOCOL_TYPE = \"TCP\"\nLISTEN_IP = \"127.0.0.1\"\nLISTEN_PORT = %d\nDOMAINS = [\"a.test\"]\nDATA_ENCRYPTION_METHOD = %d\nENCRYPTION_KEY = %q\nRESOLVER_TRANSPORT = \"udp\"\nSTARTUP_MODE = \"resolvers\"\nTERMINAL_UI = \"plain\"\nLOG_TO_FILE = false\nRESOLVER_DISCOVERY_ENABLED = false\nRESOLVER_DISCOVERY_SAMPLE_RANGES = 0\nCOTTENMAX_SAFE_QNAME = %d\nCOTTENMAX_MAX_QNAME = %d\nCOTTENMAX_MAX_ANSWER = %d\nCOTTENMAX_FEC_DOWNLOAD_ENABLED = false\nLOG_LEVEL = \"INFO\"\n", preset, tunnel, profile, clientPort, method, key, o.Name, o.Name, o.Answer)
	if o.LowReduction > 0 {
		clientCfg += fmt.Sprintf("COTTENMAX_LOW_REDUCTION_PERCENT = %d\n", o.LowReduction)
	}
	if o.Mode == "normal-android" && o.NormalTemplate == "" {
		clientCfg += "MIN_UPLOAD_MTU = 40\nMAX_UPLOAD_MTU = 140\nMIN_DOWNLOAD_MTU = 300\nMAX_DOWNLOAD_MTU = 3000\nMTU_TEST_TIMEOUT_RESOLVERS = 2.5\nMTU_TEST_RETRIES_RESOLVERS = 3\n"
	}
	if o.NormalTemplate != "" && strings.HasPrefix(o.Mode, "normal-") {
		var template, overrides map[string]any
		if _, e = toml.DecodeFile(o.NormalTemplate, &template); e != nil {
			return fail(e)
		}
		if _, e = toml.Decode(clientCfg, &overrides); e != nil {
			return fail(e)
		}
		for key, value := range overrides {
			template[key] = value
		}
		var merged bytes.Buffer
		if e = toml.NewEncoder(&merged).Encode(template); e != nil {
			return fail(e)
		}
		clientCfg = merged.String()
	}
	if o.TunedMTU {
		if o.MinUploadMTU < 0 {
			o.MinUploadMTU = 8
		}
		if o.MinDownloadMTU < 0 {
			o.MinDownloadMTU = 16
		}
	}
	if o.MinUploadMTU >= 0 || o.MinDownloadMTU >= 0 {
		var values map[string]any
		if _, e = toml.Decode(clientCfg, &values); e != nil {
			return fail(e)
		}
		if o.MinUploadMTU >= 0 {
			values["MIN_UPLOAD_MTU"] = o.MinUploadMTU
		}
		if o.MinDownloadMTU >= 0 {
			values["MIN_DOWNLOAD_MTU"] = o.MinDownloadMTU
		}
		var encoded bytes.Buffer
		if e = toml.NewEncoder(&encoded).Encode(values); e != nil {
			return fail(e)
		}
		clientCfg = encoded.String()
	}
	r.Options = o
	for p, data := range map[string]string{"server.toml": serverCfg, "client.toml": clientCfg, "encrypt_key.txt": key, "client_resolvers.txt": front.LocalAddr().String() + "\n"} {
		if e := os.WriteFile(filepath.Join(o.Output, p), []byte(data), 0600); e != nil {
			return fail(e)
		}
	}
	start := time.Now()
	stop, e := launch(ctx, o.Server, filepath.Join(o.Output, "server.toml"), filepath.Join(o.Output, "server.log"))
	if e != nil {
		return fail(e)
	}
	defer stop()
	// The resolver relay remains running for both startup discovery and payload.
	stopClient, e := launch(ctx, o.Client, filepath.Join(o.Output, "client.toml"), filepath.Join(o.Output, "client.log"))
	if e != nil {
		return fail(e)
	}
	defer stopClient()
	proxy := fmt.Sprintf("127.0.0.1:%d", clientPort)
	if e = waitReady(ctx, proxy, filepath.Join(o.Output, "client.log")); e != nil {
		r.ColdSeconds = time.Since(start).Seconds()
		r.ColdTraffic = re.c.snapshot()
		return fail(fmt.Errorf("client readiness: %w", e))
	}
	warm, e := openForward(ctx, proxy, "upload", 0, 0)
	if e != nil {
		return fail(fmt.Errorf("warm forward: %w", e))
	}
	if _, e = warm.Write([]byte("G")); e == nil {
		var ack [2]byte
		_, e = io.ReadFull(warm, ack[:])
		if e == nil && string(ack[:]) != "OK" {
			e = fmt.Errorf("warm acknowledgement mismatch")
		}
	}
	warm.Close()
	if e != nil {
		return fail(fmt.Errorf("warm transfer: %w", e))
	}
	r.ColdSeconds = time.Since(start).Seconds()
	r.ColdTraffic = re.c.snapshot()
	conns := make([]net.Conn, o.Flows)
	defer func() {
		for _, c := range conns {
			if c != nil {
				c.Close()
			}
		}
	}()
	errs := make(chan error, o.Flows)
	var wg sync.WaitGroup
	before := re.c.snapshot()
	beforeDials := accepted.Load()
	start = time.Now()
	for i := range conns {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, e := openForward(ctx, proxy, o.Direction, i, o.Bytes)
			if e != nil {
				errs <- e
				return
			}
			conns[i] = c
		}(i)
	}
	wg.Wait()
	r.OpenSeconds = time.Since(start).Seconds()
	r.SetupTraffic = difference(re.c.snapshot(), before)
	r.TargetConnections = accepted.Load() - beforeDials
	r.TargetCPS = float64(r.TargetConnections) / r.OpenSeconds
	if len(errs) > 0 {
		return fail(fmt.Errorf("stream open: %w", <-errs))
	}
	before = re.c.snapshot()
	start = time.Now()
	for i, c := range conns {
		wg.Add(1)
		go func(i int, c net.Conn) {
			defer wg.Done()
			if _, e := c.Write([]byte("G")); e != nil {
				errs <- e
				return
			}
			if o.Direction == "upload" {
				if _, e := io.Copy(c, bytes.NewReader(payloads[i])); e != nil {
					errs <- e
					return
				}
			} else {
				got := make([]byte, o.Bytes)
				if _, e := io.ReadFull(c, got); e != nil {
					errs <- e
					return
				}
				if !bytes.Equal(got, payloads[i]) {
					errs <- fmt.Errorf("download mismatch")
					return
				}
			}
			var ack [2]byte
			if _, e := io.ReadFull(c, ack[:]); e != nil {
				errs <- e
				return
			}
			if string(ack[:]) != "OK" {
				errs <- fmt.Errorf("payload acknowledgement mismatch")
			}
		}(i, c)
	}
	wg.Wait()
	r.Seconds = time.Since(start).Seconds()
	r.Traffic = difference(re.c.snapshot(), before)
	r.QueryPS = float64(r.Traffic.Queries) / r.Seconds
	if len(errs) > 0 {
		return fail(fmt.Errorf("payload: %w", <-errs))
	}
	r.Verified = o.Bytes * o.Flows
	r.Mbps = float64(r.Verified) * 8 / r.Seconds / 1e6
	return r
}

func main() {
	var o options
	flag.StringVar(&o.Mode, "mode", "normal-default-aes128", "normal-default-xor,normal-default-aes128,normal-speed-aes128,max-low,max-full")
	flag.StringVar(&o.Direction, "direction", "download", "upload or download")
	flag.IntVar(&o.Flows, "flows", 1, "concurrent fixed TCP-forward streams")
	flag.IntVar(&o.Bytes, "bytes", 262144, "verified incompressible bytes per stream")
	flag.IntVar(&o.RTT, "rtt", 80, "DNS round-trip milliseconds")
	flag.Float64Var(&o.Loss, "loss", 0, "independent query/answer loss")
	flag.IntVar(&o.Name, "qname", 253, "maximum presentation-format DNS question name")
	flag.IntVar(&o.Answer, "answer", 1232, "maximum UDP DNS response bytes")
	flag.Int64Var(&o.Seed, "seed", 3400, "payload and loss sequence seed")
	flag.IntVar(&o.Timeout, "timeout", 180, "maximum seconds including startup")
	flag.BoolVar(&o.TunedMTU, "tuned-normal-mtu", false, "explicitly lower Normal minimum MTU to 8/16; otherwise leave stock preset bounds")
	flag.IntVar(&o.MinUploadMTU, "normal-min-upload-mtu", -1, "Normal minimum upload MTU override (-1 preserves preset)")
	flag.IntVar(&o.MinDownloadMTU, "normal-min-download-mtu", -1, "Normal minimum download MTU override (-1 preserves preset)")
	flag.StringVar(&o.NormalTemplate, "normal-template", "", "actual Normal app-generated TOML template; local network/key/mode settings are replaced")
	flag.IntVar(&o.NormalMethod, "normal-method", -1, "Normal encryption method override (-1 preserves selected mode)")
	flag.IntVar(&o.LowReduction, "low-reduction", 0, "Max Low percentage reduction (0 uses production default)")
	flag.StringVar(&o.RelayOrder, "relay-order", "ordered", "ordered delay queues, or timer for reproducing the legacy jitter model")
	flag.StringVar(&o.Client, "client", ".bench/normalmax/client.exe", "production client binary")
	flag.StringVar(&o.Server, "server", ".bench/normalmax/server.exe", "production server binary")
	flag.StringVar(&o.Output, "runtime-dir", "", "runtime config/log directory (retained)")
	flag.Parse()
	valid := map[string]bool{"normal-default-xor": true, "normal-default-aes128": true, "normal-speed-aes128": true, "normal-android": true, "normal-desktop": true, "max-low": true, "max-low-10": true, "max-low-35": true, "max-low-90": true, "max-full": true}
	if strings.HasPrefix(o.Mode, "max-low-") && o.LowReduction == 0 {
		switch o.Mode {
		case "max-low-10":
			o.LowReduction = 10
		case "max-low-35":
			o.LowReduction = 35
		case "max-low-90":
			o.LowReduction = 90
		}
	}
	if !valid[o.Mode] || (o.Direction != "download" && o.Direction != "upload") || o.Flows < 1 || o.Flows > 16 || o.Bytes < 1 || o.Bytes > 16<<20 || o.RTT < 0 || o.Loss < 0 || o.Loss >= 1 || o.Name < 101 || o.Name > 253 || o.Answer < 512 || o.Answer > 4096 || o.Timeout < 1 {
		fmt.Fprintln(os.Stderr, "invalid options")
		os.Exit(2)
	}
	var e error
	o.Client, e = filepath.Abs(o.Client)
	if e != nil {
		panic(e)
	}
	o.Server, e = filepath.Abs(o.Server)
	if e != nil {
		panic(e)
	}
	if o.Output == "" {
		if e = os.MkdirAll(".bench/normalmax", 0755); e != nil {
			panic(e)
		}
		o.Output, e = os.MkdirTemp(".bench/normalmax", "case-")
		if e != nil {
			panic(e)
		}
	}
	o.Output, e = filepath.Abs(o.Output)
	if e != nil {
		panic(e)
	}
	r := bench(o)
	_ = json.NewEncoder(os.Stdout).Encode(r)
	if r.Error != "" {
		os.Exit(1)
	}
}
