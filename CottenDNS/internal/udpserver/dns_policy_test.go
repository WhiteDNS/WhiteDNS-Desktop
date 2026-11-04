package udpserver

import (
	"encoding/binary"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"cottendns-go/internal/config"
	"cottendns-go/internal/cottenmax"
)

func TestStandaloneNormalAndMaxDNSCachesKeepQueryPoliciesSeparate(t *testing.T) {
	upstream, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	base := embeddedTestDNSQuery(t, "example.com", 1)
	baseResponse := embeddedTestDNSResponse(t, base, 60)
	var calls atomic.Uint32
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 4096)
		for {
			n, peer, err := upstream.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			if n < 2 {
				continue
			}
			response := append([]byte(nil), baseResponse...)
			copy(response[:2], buffer[:2])
			response[len(response)-1] = byte(calls.Add(1))
			upstream.WriteToUDP(response, peer)
		}
	}()
	defer func() { upstream.Close(); <-done }()
	cfg := config.DefaultServerConfig()
	cfg.DNSUpstreamServers = []string{upstream.LocalAddr().String()}
	s := New(cfg, nil, nil)
	queries := make([][]byte, 5)
	for i := range queries {
		queries[i] = append([]byte(nil), base...)
	}
	queries[1][3] |= 0x10
	queries[2][len(base)-4] |= 0x80
	queries[3][3] |= 0x10
	queries[3][len(base)-4] |= 0x80
	binary.BigEndian.PutUint16(queries[4][len(base)-8:len(base)-6], 1400)
	for i, query := range queries {
		response := s.buildDNSQueryResponsePayload(query, 1, uint16(i))
		if len(response) == 0 || response[len(response)-1] != byte(i+1) {
			t.Fatalf("Normal policy %d reused another policy's answer", i)
		}
	}
	for i, query := range queries {
		binary.BigEndian.PutUint16(query, uint16(100+i))
		stream := s.cottenMaxDNSStream()
		stream.SetDeadline(time.Now().Add(3 * time.Second))
		if err := cottenmax.WriteDNSFrame(stream, query); err != nil {
			stream.Close()
			t.Fatal(err)
		}
		response, err := cottenmax.ReadDNSFrame(stream)
		stream.Close()
		if err != nil || len(response) == 0 || response[len(response)-1] != byte(i+1) || binary.BigEndian.Uint16(response) != uint16(100+i) {
			t.Fatalf("Max policy %d lost isolated cached answer: %v", i, err)
		}
	}
	if calls.Load() != uint32(len(queries)) {
		t.Fatalf("same-policy queries did not share the cache across Normal/Max: calls=%d", calls.Load())
	}
}
