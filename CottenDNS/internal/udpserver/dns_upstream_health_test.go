package udpserver

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"cottendns-go/internal/config"
)

func TestOrderedDNSUpstreamsDeprioritizesRepeatedFailures(t *testing.T) {
	s := &Server{
		dnsUpstreamServers: []string{"slow", "healthy"},
		dnsUpstreamHealth:  make(map[string]*dnsUpstreamHealthState),
	}
	s.recordDNSUpstreamResult("slow", time.Second, false)
	s.recordDNSUpstreamResult("slow", time.Second, false)
	s.recordDNSUpstreamResult("healthy", 20*time.Millisecond, true)

	ordered := s.orderedDNSUpstreams(time.Now())
	if len(ordered) != 2 || ordered[0] != "healthy" {
		t.Fatalf("expected healthy upstream first, got %v", ordered)
	}
}

func TestQueryOneUpstreamRetriesTruncatedUDPOverTCP(t *testing.T) {
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpListener.Close()
	port := tcpListener.Addr().(*net.TCPAddr).Port
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()

	query := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	want := []byte{0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0}
	go func() {
		buffer := make([]byte, 512)
		n, addr, readErr := udpConn.ReadFromUDP(buffer)
		if readErr == nil {
			truncated := append([]byte(nil), buffer[:n]...)
			truncated[2] |= 0x02
			_, _ = udpConn.WriteToUDP(truncated, addr)
		}
	}()
	go func() {
		conn, acceptErr := tcpListener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		var size [2]byte
		if _, readErr := io.ReadFull(conn, size[:]); readErr != nil {
			return
		}
		request := make([]byte, binary.BigEndian.Uint16(size[:]))
		if _, readErr := io.ReadFull(conn, request); readErr != nil {
			return
		}
		frame := make([]byte, 2+len(want))
		binary.BigEndian.PutUint16(frame[:2], uint16(len(want)))
		copy(frame[2:], want)
		_, _ = conn.Write(frame)
	}()

	s := &Server{dnsUpstreamBufferPool: sync.Pool{New: func() any { return make([]byte, 65535) }}}
	got, err := s.queryOneUpstream(tcpListener.Addr().String(), query, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) || s.dnsUpstreamTCPFallbacks.Load() != 1 {
		t.Fatalf("unexpected fallback response=%x fallbacks=%d", got, s.dnsUpstreamTCPFallbacks.Load())
	}
}

func TestMetricsHandlerExposesHealthAndCounters(t *testing.T) {
	s := &Server{
		cfg: config.ServerConfig{
			MaxConcurrentRequests: 64,
			MaxPacketSize:         1024,
			MaxIngressQueueBytes:  64 * 1024,
			MaxActiveSessions:     2048,
			MaxStreamsPerSession:  4096,
			TCPMaxConns:           1024,
			UDPReaders:            4,
			DNSRequestWorkers:     8,
			SocketBufferSize:      8 * 1024 * 1024,
		},
		sessions:           &sessionStore{},
		startedAt:          time.Now().Add(-90 * time.Second),
		dnsUpstreamHealth:  make(map[string]*dnsUpstreamHealthState),
		externalSOCKS5User: []byte("must-not-leak"),
	}
	s.running.Store(true)
	s.dnsUpstreamQueries.Store(7)
	s.codecAccepted[3].Store(11)
	s.genericUDPActive.Store(2)
	s.genericUDPDownBytes.Store(4096)

	health := httptest.NewRecorder()
	s.MetricsHandler().ServeHTTP(health, httptest.NewRequest("GET", "/healthz", nil))
	if health.Code != 200 || health.Body.String() != "ok\n" {
		t.Fatalf("unexpected health response: %d %q", health.Code, health.Body.String())
	}

	detailed := httptest.NewRecorder()
	s.MetricsHandler().ServeHTTP(detailed, httptest.NewRequest("GET", "/healthz?details=1", nil))
	if detailed.Code != http.StatusOK {
		t.Fatalf("unexpected detailed health status: %d", detailed.Code)
	}
	var snapshot healthResponse
	if err := json.Unmarshal(detailed.Body.Bytes(), &snapshot); err != nil {
		t.Fatalf("decode detailed health: %v\n%s", err, detailed.Body.String())
	}
	if snapshot.Status != "ok" || snapshot.UptimeSeconds < 89 {
		t.Fatalf("unexpected detailed status/uptime: %+v", snapshot)
	}
	if snapshot.Capacity.IngressControlQueueSlots+snapshot.Capacity.IngressDataQueueSlots != 64 {
		t.Fatalf("unexpected ingress capacity: %+v", snapshot.Capacity)
	}
	foundQueries, foundCodec, foundUDP := false, false, false
	for _, metric := range snapshot.Monitoring {
		switch metric.Name {
		case "dns_upstream_queries_total":
			foundQueries = metric.Value == 7 && metric.Type == "counter"
		case "ingress_codec_method_3_packets_total":
			foundCodec = metric.Value == 11
		case "generic_udp_downstream_bytes_total":
			foundUDP = metric.Value == 4096 && metric.Type == "counter"
		}
	}
	if !foundQueries || !foundCodec || !foundUDP {
		t.Fatalf("detailed monitoring list missing counters: queries=%t codec=%t udp=%t", foundQueries, foundCodec, foundUDP)
	}
	if strings.Contains(detailed.Body.String(), "must-not-leak") {
		t.Fatal("detailed health leaked a credential")
	}

	metrics := httptest.NewRecorder()
	s.MetricsHandler().ServeHTTP(metrics, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(metrics.Body.String(), "cottendns_dns_upstream_queries_total 7") {
		t.Fatalf("missing upstream counter: %s", metrics.Body.String())
	}
	if !strings.Contains(metrics.Body.String(), "# TYPE cottendns_dns_upstream_queries_total counter") ||
		!strings.Contains(metrics.Body.String(), "cottendns_runtime_heap_alloc_bytes") {
		t.Fatalf("missing metric type or runtime monitoring: %s", metrics.Body.String())
	}
}
