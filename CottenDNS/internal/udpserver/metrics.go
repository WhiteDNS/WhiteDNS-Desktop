package udpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"strings"
	"time"

	"cottendns-go/internal/version"
)

type monitoringMetric struct {
	Name  string `json:"name"`
	Value uint64 `json:"value"`
	Type  string `json:"type"`
	Unit  string `json:"unit,omitempty"`
}

type healthRuntime struct {
	GOOS              string `json:"goos"`
	GOARCH            string `json:"goarch"`
	GoVersion         string `json:"go_version"`
	GOMAXPROCS        int    `json:"gomaxprocs"`
	Goroutines        int    `json:"goroutines"`
	HeapAllocBytes    uint64 `json:"heap_alloc_bytes"`
	HeapInUseBytes    uint64 `json:"heap_in_use_bytes"`
	SystemMemoryBytes uint64 `json:"system_memory_bytes"`
	GCCycles          uint32 `json:"gc_cycles"`
}

type healthCapacity struct {
	MaxActiveSessions        int `json:"max_active_sessions"`
	MaxStreamsPerSession     int `json:"max_streams_per_session"`
	MaxTCPConnections        int `json:"max_tcp_connections"`
	UDPReaders               int `json:"udp_readers"`
	DNSWorkers               int `json:"dns_workers"`
	SocketBufferBytes        int `json:"socket_buffer_bytes"`
	MaxIngressQueueBytes     int `json:"max_ingress_queue_bytes"`
	IngressControlQueueSlots int `json:"ingress_control_queue_slots"`
	IngressDataQueueSlots    int `json:"ingress_data_queue_slots"`
}

type healthTransports struct {
	UDPEnabled        bool `json:"udp_enabled"`
	UDPUp             bool `json:"udp_up"`
	TCPEnabled        bool `json:"tcp_enabled"`
	TCPUp             bool `json:"tcp_up"`
	DoTEnabled        bool `json:"dot_enabled"`
	DoTUp             bool `json:"dot_up"`
	DoHEnabled        bool `json:"doh_enabled"`
	DoHUp             bool `json:"doh_up"`
	ExternalSOCKS5    bool `json:"external_socks5"`
	SNIPassthroughNow bool `json:"sni_passthrough_active"`
}

type healthDNSUpstreams struct {
	Configured          int     `json:"configured"`
	Observed            int     `json:"observed"`
	CoolingDown         int     `json:"cooling_down"`
	MaxConsecutiveFails int     `json:"max_consecutive_failures"`
	AverageEWMAMillis   float64 `json:"average_ewma_latency_ms"`
}

type healthResponse struct {
	Status        string             `json:"status"`
	Version       string             `json:"version"`
	GeneratedAt   time.Time          `json:"generated_at"`
	UptimeSeconds uint64             `json:"uptime_seconds"`
	Runtime       healthRuntime      `json:"runtime"`
	Capacity      healthCapacity     `json:"capacity"`
	Transports    healthTransports   `json:"transports"`
	DNSUpstreams  healthDNSUpstreams `json:"dns_upstreams"`
	Warnings      []string           `json:"warnings"`
	Monitoring    []monitoringMetric `json:"monitoring"`
}

func metricList(stats Stats, uptimeSeconds uint64, mem runtime.MemStats) []monitoringMetric {
	metrics := make([]monitoringMetric, 0, 52)
	add := func(name string, value uint64, metricType string, unit string) {
		metrics = append(metrics, monitoringMetric{Name: name, Value: value, Type: metricType, Unit: unit})
	}

	add("uptime_seconds", uptimeSeconds, "gauge", "seconds")
	add("active_sessions", stats.ActiveSessions, "gauge", "sessions")
	add("active_streams", stats.ActiveStreams, "gauge", "streams")
	add("native_sessions", stats.NativeSessions, "gauge", "sessions")
	add("legacy_sessions", stats.LegacySessions, "gauge", "sessions")
	add("dropped_packets_total", stats.DroppedPackets, "counter", "packets")
	add("ingress_rejected_packets_total", stats.IngressRejectedPackets, "counter", "packets")
	add("ingress_prepared_packets_total", stats.IngressPreparedPackets, "counter", "packets")
	add("ingress_inflate_failures_total", stats.IngressInflateFailures, "counter", "packets")
	add("ingress_control_queue_depth", stats.IngressControlDepth, "gauge", "requests")
	add("ingress_data_queue_depth", stats.IngressDataDepth, "gauge", "requests")
	add("ingress_control_queue_capacity", stats.IngressControlCapacity, "gauge", "requests")
	add("ingress_data_queue_capacity", stats.IngressDataCapacity, "gauge", "requests")
	add("ingress_control_queue_high_water", stats.IngressControlHighWater, "gauge", "requests")
	add("ingress_data_queue_high_water", stats.IngressDataHighWater, "gauge", "requests")
	add("ingress_processing_latency_nanoseconds_total", stats.IngressLatencyNanos, "counter", "nanoseconds")
	add("ingress_processing_latency_samples_total", stats.IngressLatencySamples, "counter", "samples")
	add("deferred_dns_pending", stats.DeferredDNSPending, "gauge", "tasks")
	add("deferred_dns_capacity", stats.DeferredDNSCapacity, "gauge", "tasks")
	add("deferred_connect_pending", stats.DeferredConnectPending, "gauge", "tasks")
	add("deferred_connect_capacity", stats.DeferredConnectCapacity, "gauge", "tasks")
	add("deferred_dropped_packets_total", stats.DeferredDroppedPackets, "counter", "packets")
	add("stream_cap_rejections_total", stats.StreamCapRejections, "counter", "streams")
	add("session_busy_responses_total", stats.SessionBusyResponses, "counter", "responses")
	add("stream_connections_active", stats.StreamConnectionsActive, "gauge", "connections")
	add("stream_connections_limit", stats.StreamConnectionsLimit, "gauge", "connections")
	add("encrypted_connections_active", stats.EncryptedConnsActive, "gauge", "connections")
	add("encrypted_connections_limit", stats.EncryptedConnsLimit, "gauge", "connections")
	add("dns_response_oversize_total", stats.DNSResponseOversize, "counter", "responses")
	add("fragment_conflict_drops_total", stats.FragmentConflictDrops, "counter", "fragments")
	add("fragment_invalid_header_total", stats.FragmentInvalidHeader, "counter", "fragments")
	add("dns_upstream_queries_total", stats.DNSUpstreamQueries, "counter", "queries")
	add("dns_upstream_failures_total", stats.DNSUpstreamFailures, "counter", "queries")
	add("dns_upstream_hedges_total", stats.DNSUpstreamHedges, "counter", "queries")
	add("dns_upstream_tcp_fallbacks_total", stats.DNSUpstreamTCPFallbacks, "counter", "queries")
	add("tcp_listener_up", stats.TCPListenerUp, "gauge", "boolean")
	add("dot_listener_up", stats.DoTListenerUp, "gauge", "boolean")
	add("doh_listener_up", stats.DoHListenerUp, "gauge", "boolean")
	add("tls_handshake_failures_total", stats.TLSHandshakeFailures, "counter", "connections")
	add("encrypted_connection_rejections_total", stats.EncryptedConnRejected, "counter", "connections")
	add("doh_request_rejections_total", stats.DoHRequestRejected, "counter", "requests")
	add("sni_passthrough_active", stats.SNIPassthroughActive, "gauge", "connections")
	add("sni_passthrough_failures_total", stats.SNIPassthroughFailures, "counter", "connections")
	add("upstream_panics_recovered_total", stats.UpstreamPanicsRecovered, "counter", "panics")
	add("cleanup_panics_recovered_total", stats.CleanupPanicsRecovered, "counter", "panics")
	add("generic_udp_associations_active", stats.GenericUDPActive, "gauge", "associations")
	add("generic_udp_associations_total", stats.GenericUDPTotal, "counter", "associations")
	add("generic_udp_endpoints_active", stats.GenericUDPEndpoints, "gauge", "endpoints")
	add("generic_udp_upstream_datagrams_total", stats.GenericUDPUpDatagrams, "counter", "datagrams")
	add("generic_udp_upstream_bytes_total", stats.GenericUDPUpBytes, "counter", "bytes")
	add("generic_udp_downstream_datagrams_total", stats.GenericUDPDownDatagrams, "counter", "datagrams")
	add("generic_udp_downstream_bytes_total", stats.GenericUDPDownBytes, "counter", "bytes")
	add("generic_udp_errors_total", stats.GenericUDPErrors, "counter", "errors")
	for method, accepted := range stats.CodecAcceptedPackets {
		add(fmt.Sprintf("ingress_codec_method_%d_packets_total", method), accepted, "counter", "packets")
	}
	add("runtime_goroutines", uint64(runtime.NumGoroutine()), "gauge", "goroutines")
	add("runtime_heap_alloc_bytes", mem.HeapAlloc, "gauge", "bytes")
	add("runtime_heap_in_use_bytes", mem.HeapInuse, "gauge", "bytes")
	add("runtime_system_memory_bytes", mem.Sys, "gauge", "bytes")
	add("runtime_gc_cycles_total", uint64(mem.NumGC), "counter", "cycles")
	return metrics
}

func (s *Server) uptime(now time.Time) uint64 {
	if s == nil || s.startedAt.IsZero() || now.Before(s.startedAt) {
		return 0
	}
	return uint64(now.Sub(s.startedAt) / time.Second)
}

func (s *Server) dnsUpstreamSnapshot(now time.Time) healthDNSUpstreams {
	if s == nil {
		return healthDNSUpstreams{}
	}
	result := healthDNSUpstreams{Configured: len(s.dnsUpstreamServers)}
	s.dnsUpstreamHealthMu.Lock()
	var latencyTotal time.Duration
	var latencySamples int
	for _, state := range s.dnsUpstreamHealth {
		if state == nil {
			continue
		}
		result.Observed++
		if now.Before(state.cooldownUntil) {
			result.CoolingDown++
		}
		if state.consecutiveFailures > result.MaxConsecutiveFails {
			result.MaxConsecutiveFails = state.consecutiveFailures
		}
		if state.ewmaLatency > 0 {
			latencyTotal += state.ewmaLatency
			latencySamples++
		}
	}
	s.dnsUpstreamHealthMu.Unlock()
	if latencySamples > 0 {
		result.AverageEWMAMillis = float64(latencyTotal) / float64(latencySamples) / float64(time.Millisecond)
	}
	return result
}

func queuePressureWarning(name string, depth uint64, capacity uint64) string {
	if capacity == 0 || depth*100 < capacity*85 {
		return ""
	}
	return fmt.Sprintf("%s is at %d%% capacity", name, depth*100/capacity)
}

func (s *Server) detailedHealth(now time.Time) healthResponse {
	stats := s.Stats()
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	status := "starting"
	if s != nil && s.running.Load() {
		status = "ok"
	}
	warnings := make([]string, 0, 4)
	for _, warning := range []string{
		queuePressureWarning("ingress control queue", stats.IngressControlDepth, stats.IngressControlCapacity),
		queuePressureWarning("ingress data queue", stats.IngressDataDepth, stats.IngressDataCapacity),
		queuePressureWarning("deferred DNS queue", stats.DeferredDNSPending, stats.DeferredDNSCapacity),
		queuePressureWarning("deferred connect queue", stats.DeferredConnectPending, stats.DeferredConnectCapacity),
	} {
		if warning != "" {
			warnings = append(warnings, warning)
		}
	}
	dnsUpstreams := s.dnsUpstreamSnapshot(now)
	if dnsUpstreams.CoolingDown > 0 {
		warnings = append(warnings, fmt.Sprintf("%d DNS upstream(s) are cooling down", dnsUpstreams.CoolingDown))
	}
	if s.running.Load() && s.cfg.TCPListenerEnabled && stats.TCPListenerUp == 0 {
		warnings = append(warnings, "TCP listener is configured but not ready")
	}
	if s.running.Load() && s.cfg.DoTListenerEnabled && stats.DoTListenerUp == 0 {
		warnings = append(warnings, "DoT listener is configured but not ready")
	}
	if s.running.Load() && s.cfg.DoHListenerEnabled && stats.DoHListenerUp == 0 {
		warnings = append(warnings, "DoH listener is configured but not ready")
	}

	controlCapacity, dataCapacity := s.ingressQueueCapacities()
	return healthResponse{
		Status:        status,
		Version:       version.GetVersion(),
		GeneratedAt:   now.UTC(),
		UptimeSeconds: s.uptime(now),
		Runtime: healthRuntime{
			GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, GoVersion: runtime.Version(),
			GOMAXPROCS: runtime.GOMAXPROCS(0), Goroutines: runtime.NumGoroutine(),
			HeapAllocBytes: mem.HeapAlloc, HeapInUseBytes: mem.HeapInuse,
			SystemMemoryBytes: mem.Sys, GCCycles: mem.NumGC,
		},
		Capacity: healthCapacity{
			MaxActiveSessions: s.cfg.MaxActiveSessions, MaxStreamsPerSession: s.cfg.MaxStreamsPerSession,
			MaxTCPConnections: s.cfg.TCPMaxConns, UDPReaders: s.cfg.UDPReaders,
			DNSWorkers: s.cfg.DNSRequestWorkers, SocketBufferBytes: s.cfg.SocketBufferSize,
			MaxIngressQueueBytes:     s.cfg.MaxIngressQueueBytes,
			IngressControlQueueSlots: controlCapacity, IngressDataQueueSlots: dataCapacity,
		},
		Transports: healthTransports{
			UDPEnabled: true, UDPUp: s.running.Load(),
			TCPEnabled: s.cfg.TCPListenerEnabled, TCPUp: stats.TCPListenerUp != 0,
			DoTEnabled: s.cfg.DoTListenerEnabled, DoTUp: stats.DoTListenerUp != 0,
			DoHEnabled: s.cfg.DoHListenerEnabled, DoHUp: stats.DoHListenerUp != 0,
			ExternalSOCKS5: s.useExternalSOCKS5, SNIPassthroughNow: stats.SNIPassthroughActive != 0,
		},
		DNSUpstreams: dnsUpstreams,
		Warnings:     warnings,
		Monitoring:   metricList(stats, s.uptime(now), mem),
	}
}

func wantsDetailedHealth(r *http.Request) bool {
	if r == nil {
		return false
	}
	detail := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("details")))
	return detail == "1" || detail == "true" || detail == "full" ||
		strings.Contains(strings.ToLower(r.Header.Get("Accept")), "application/json")
}

// MetricsHandler exposes dependency-free Prometheus monitoring and a backward-
// compatible liveness endpoint. Detailed health never includes keys, client
// addresses, queried domains, destinations, or payload data.
func (s *Server) MetricsHandler() http.Handler {
	mux := http.NewServeMux()
	healthHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		if !wantsDetailedHealth(r) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte("ok\n"))
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(s.detailedHealth(time.Now()))
	}
	mux.HandleFunc("/healthz", healthHandler)
	mux.HandleFunc("/healthz/details", healthHandler)
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		stats := s.Stats()
		now := time.Now()
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)
		_, _ = fmt.Fprintf(w, "# TYPE cottendns_build_info gauge\ncottendns_build_info{version=%q} 1\n", version.GetVersion())
		for _, metric := range metricList(stats, s.uptime(now), mem) {
			_, _ = fmt.Fprintf(w, "# TYPE cottendns_%s %s\ncottendns_%s %d\n", metric.Name, metric.Type, metric.Name, metric.Value)
		}
	})
	return mux
}

func (s *Server) ServeMetrics(ctx context.Context, listener net.Listener) error {
	server := &http.Server{
		Handler:           s.MetricsHandler(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = server.Shutdown(shutdownCtx)
		case <-done:
		}
	}()
	err := server.Serve(listener)
	close(done)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}
