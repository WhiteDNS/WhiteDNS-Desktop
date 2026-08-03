// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================

package udpserver

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"cottendns-go/internal/config"
	DnsParser "cottendns-go/internal/dnsparser"
	Enums "cottendns-go/internal/enums"
	"cottendns-go/internal/logger"
	"cottendns-go/internal/security"
	VpnProto "cottendns-go/internal/vpnproto"
)

// writeTCPDNSMessage frames and writes one length-prefixed DNS message.
func writeTCPDNSMessage(conn net.Conn, msg []byte) error {
	buf := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(msg)))
	copy(buf[2:], msg)
	_, err := conn.Write(buf)
	return err
}

// readTCPDNSMessage reads one length-prefixed DNS message.
func readTCPDNSMessage(conn net.Conn) ([]byte, error) {
	var l [2]byte
	if _, err := io.ReadFull(conn, l[:]); err != nil {
		return nil, err
	}
	msg := make([]byte, binary.BigEndian.Uint16(l[:]))
	if _, err := io.ReadFull(conn, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

func TestServeTCPDNSMessages_FramingRoundTrip(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	// Handler echoes the query back with a one-byte tag, proving the framing
	// carries the exact message both ways and supports pipelining.
	handler := func(q []byte) []byte {
		return append(append([]byte{}, q...), 0xAA)
	}
	go func() {
		serveTCPDNSMessages(context.Background(), server, handler)
		server.Close()
	}()

	for i := 0; i < 3; i++ {
		query := []byte{byte(i), 0x01, 0x02, 0x03}
		if err := writeTCPDNSMessage(client, query); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
		resp, err := readTCPDNSMessage(client)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if len(resp) != len(query)+1 || resp[len(resp)-1] != 0xAA {
			t.Fatalf("response %d malformed: %v", i, resp)
		}
		for j := range query {
			if resp[j] != query[j] {
				t.Fatalf("response %d payload mismatch at %d", i, j)
			}
		}
	}
}

func TestServeTCPDNSMessages_EmptyResponseKeepsConnOpen(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	calls := 0
	handler := func(q []byte) []byte {
		calls++
		if calls == 1 {
			return nil // no tunnel response -> connection must stay open
		}
		return []byte{0x99}
	}
	go func() {
		serveTCPDNSMessages(context.Background(), server, handler)
		server.Close()
	}()

	_ = writeTCPDNSMessage(client, []byte{0x01})
	_ = writeTCPDNSMessage(client, []byte{0x02})
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp, err := readTCPDNSMessage(client)
	if err != nil {
		t.Fatalf("expected a response after an empty one: %v", err)
	}
	if len(resp) != 1 || resp[0] != 0x99 {
		t.Fatalf("unexpected response: %v", resp)
	}
}

func TestTCPFallbackUsesSameDynamicEncryptedCarrierHandler(t *testing.T) {
	const sharedKey = "tcp-fallback-shared-key"
	preferred, err := security.NewCodec(1, sharedKey)
	if err != nil {
		t.Fatal(err)
	}
	s := New(config.ServerConfig{
		Domain:                            []string{"v.example.com"},
		MinVPNLabelLength:                 3,
		SessionOrphanQueueInitialCap:      8,
		StreamQueueInitialCapacity:        8,
		DNSFragmentStoreCapacity:          8,
		SOCKS5FragmentStoreCapacity:       8,
		MaxStreamsPerSession:              16,
		MaxActiveSessions:                 16,
		DNSCacheMaxRecords:                16,
		DNSCacheTTLSeconds:                60,
		MaxPacketSize:                     4096,
		MaxPacketsPerBatch:                1,
		SupportedUploadCompressionTypes:   []int{0},
		SupportedDownloadCompressionTypes: []int{0},
	}, logger.New("tcp-fallback-test", "ERROR"), preferred)
	methods := security.AutoDetectMethods(1)
	codecSet, err := security.NewCodecSet(methods, sharedKey)
	if err != nil {
		t.Fatal(err)
	}
	s.SetCodecSet(codecSet, 0)

	changedCodec, err := security.NewCodec(5, sharedKey)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := VpnProto.BuildEncoded(VpnProto.BuildOptions{
		SessionID:  0,
		PacketType: Enums.PACKET_MTU_UP_REQ,
		Payload:    []byte{0, 1, 2, 3, 4},
	}, changedCodec)
	if err != nil {
		t.Fatal(err)
	}
	normalized, qname, err := DnsParser.PrepareTunnelDomainQname("v.example.com")
	if err != nil {
		t.Fatal(err)
	}
	query, err := DnsParser.BuildTunnelQuestionPacketShaped(normalized, qname, []byte(encoded), Enums.DNS_RECORD_TYPE_HTTPS, DnsParser.QueryShaping{
		EDNSUDPSize: 4096, RandomizeID: true, EDNSCookie: true, CaseRandomize: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	client, server := net.Pipe()
	defer client.Close()
	go func() {
		serveTCPDNSMessages(context.Background(), server, s.safeHandlePacket)
		_ = server.Close()
	}()
	if err := writeTCPDNSMessage(client, query); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	response, err := readTCPDNSMessage(client)
	if err != nil {
		t.Fatalf("TCP fallback did not return the Cotten response: %v", err)
	}
	if len(response) == 0 {
		t.Fatal("TCP fallback returned an empty Cotten response")
	}
}

func TestServeTCPDNSMessages_MaxQueriesPerConn(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	handler := func(q []byte) []byte {
		return append([]byte(nil), q...)
	}
	go func() {
		serveTCPDNSMessagesWithOptions(context.Background(), server, handler, tcpServerOptions{
			readIdleTimeout:   2 * time.Second,
			writeTimeout:      2 * time.Second,
			maxQueriesPerConn: 1,
		})
		server.Close()
	}()

	if err := writeTCPDNSMessage(client, []byte{0x01}); err != nil {
		t.Fatalf("first write: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := readTCPDNSMessage(client); err != nil {
		t.Fatalf("first read: %v", err)
	}

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := readTCPDNSMessage(client); err == nil {
		t.Fatal("expected connection to close after max queries")
	}
}

func TestServeTCPDNSMessagesProcessesPipelineConcurrently(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	const queryCount = 8
	started := make(chan struct{}, queryCount)
	release := make(chan struct{})
	handler := func(q []byte) []byte {
		started <- struct{}{}
		<-release
		return append([]byte(nil), q...)
	}
	go func() {
		serveTCPDNSMessagesWithOptions(context.Background(), server, handler, tcpServerOptions{
			readIdleTimeout: 2 * time.Second,
			writeTimeout:    2 * time.Second,
			maxInFlight:     queryCount,
		})
		_ = server.Close()
	}()

	for i := 0; i < queryCount; i++ {
		if err := writeTCPDNSMessage(client, []byte{byte(i + 1)}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	for i := 0; i < queryCount; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatalf("only %d/%d pipelined handlers started concurrently", i, queryCount)
		}
	}
	close(release)

	seen := make(map[byte]bool, queryCount)
	for i := 0; i < queryCount; i++ {
		_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
		response, err := readTCPDNSMessage(client)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if len(response) != 1 {
			t.Fatalf("response %d length=%d want=1", i, len(response))
		}
		seen[response[0]] = true
	}
	if len(seen) != queryCount {
		t.Fatalf("received %d/%d distinct pipelined responses", len(seen), queryCount)
	}
}

func TestReserveTCPIPSlotHonorsLimitAndRelease(t *testing.T) {
	activeByIP := map[string]int{}
	var mu sync.Mutex

	if !reserveTCPIPSlot("198.51.100.1", 1, &mu, activeByIP) {
		t.Fatal("first slot should be accepted")
	}
	if reserveTCPIPSlot("198.51.100.1", 1, &mu, activeByIP) {
		t.Fatal("second slot should be rejected at limit")
	}
	releaseTCPIPSlot("198.51.100.1", &mu, activeByIP)
	if !reserveTCPIPSlot("198.51.100.1", 1, &mu, activeByIP) {
		t.Fatal("slot should be accepted after release")
	}
}

func TestItoaPort(t *testing.T) {
	for _, tc := range []struct {
		in   int
		want string
	}{{53, "53"}, {443, "443"}, {65535, "65535"}, {0, "0"}, {-1, "0"}} {
		if got := itoaPort(tc.in); got != tc.want {
			t.Errorf("itoaPort(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
