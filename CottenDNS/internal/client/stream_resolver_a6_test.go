// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
package client

import (
	"testing"

	"cottendns-go/internal/config"
	Enums "cottendns-go/internal/enums"
)

// buildTestClientWithConnections builds a client whose connections are explicit
// (key, domain) pairs, so tests can model multiple resolvers sharing a domain.
func buildTestClientWithConnections(cfg config.ClientConfig, conns []Connection) *Client {
	c := New(cfg, nil, nil)
	c.connections = make([]Connection, len(conns))
	copy(c.connections, conns)
	c.connectionsByKey = make(map[string]int, len(conns))
	c.active_streams = make(map[uint16]*Stream_client)
	for i := range c.connections {
		c.connections[i].IsValid = true
		c.connectionsByKey[c.connections[i].Key] = i
	}
	ptrs := make([]*Connection, len(c.connections))
	for i := range c.connections {
		ptrs[i] = &c.connections[i]
	}
	c.balancer.SetConnections(ptrs)
	return c
}

func domainsOf(conns []Connection) map[string]int {
	m := make(map[string]int, len(conns))
	for _, conn := range conns {
		m[conn.Domain]++
	}
	return m
}

// Two domains, two resolvers each. With duplication=2 and A6 enabled, the two
// selected connections should span both domains rather than doubling up.
func TestA6DuplicationPrefersDistinctDomains(t *testing.T) {
	conns := []Connection{
		{Key: "d1r1", Domain: "one.example.com"},
		{Key: "d1r2", Domain: "one.example.com"},
		{Key: "d2r1", Domain: "two.example.com"},
		{Key: "d2r2", Domain: "two.example.com"},
	}

	c := buildTestClientWithConnections(config.ClientConfig{
		UploadPacketDuplicationCount:     2,
		DuplicationPreferDistinctDomains: true,
	}, conns)

	stream := testStream(11)
	stream.PreferredServerKey = "d1r1"
	c.active_streams[stream.StreamID] = stream

	selected, err := c.selectTargetConnectionsForPacket(Enums.PACKET_STREAM_DATA, stream.StreamID)
	if err != nil {
		t.Fatalf("selectTargetConnectionsForPacket: %v", err)
	}
	if len(selected) != 2 {
		t.Fatalf("selected count: got=%d want=2 (%+v)", len(selected), selected)
	}
	if d := domainsOf(selected); len(d) != 2 {
		t.Fatalf("expected 2 distinct domains, got %v (selected=%+v)", d, selected)
	}
}

// With A6 disabled, behavior is unchanged: duplicates are deduped by key only,
// so the second connection may share the preferred connection's domain.
func TestA6DisabledKeepsResolverOnlySelection(t *testing.T) {
	conns := []Connection{
		{Key: "d1r1", Domain: "one.example.com"},
		{Key: "d1r2", Domain: "one.example.com"},
		{Key: "d2r1", Domain: "two.example.com"},
	}

	c := buildTestClientWithConnections(config.ClientConfig{
		UploadPacketDuplicationCount:     2,
		DuplicationPreferDistinctDomains: false,
	}, conns)

	stream := testStream(12)
	stream.PreferredServerKey = "d1r1"
	c.active_streams[stream.StreamID] = stream

	selected, err := c.selectTargetConnectionsForPacket(Enums.PACKET_STREAM_DATA, stream.StreamID)
	if err != nil {
		t.Fatalf("selectTargetConnectionsForPacket: %v", err)
	}
	if len(selected) != 2 {
		t.Fatalf("selected count: got=%d want=2", len(selected))
	}
	// Preferred must still come first regardless of A6.
	if selected[0].Key != "d1r1" {
		t.Fatalf("expected preferred first, got=%q", selected[0].Key)
	}
}

// A6 must never under-fill: when only one domain exists, it still returns the
// full duplication count using the available resolvers on that domain.
func TestA6FallsBackToSameDomainWhenNoDiversityAvailable(t *testing.T) {
	conns := []Connection{
		{Key: "d1r1", Domain: "only.example.com"},
		{Key: "d1r2", Domain: "only.example.com"},
		{Key: "d1r3", Domain: "only.example.com"},
	}

	c := buildTestClientWithConnections(config.ClientConfig{
		UploadPacketDuplicationCount:     3,
		DuplicationPreferDistinctDomains: true,
	}, conns)

	stream := testStream(13)
	stream.PreferredServerKey = "d1r1"
	c.active_streams[stream.StreamID] = stream

	selected, err := c.selectTargetConnectionsForPacket(Enums.PACKET_STREAM_DATA, stream.StreamID)
	if err != nil {
		t.Fatalf("selectTargetConnectionsForPacket: %v", err)
	}
	if len(selected) != 3 {
		t.Fatalf("expected full duplication count 3 even with one domain, got=%d", len(selected))
	}
}
