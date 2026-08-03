package udpserver

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"cottendns-go/internal/config"
	DnsParser "cottendns-go/internal/dnsparser"
	Enums "cottendns-go/internal/enums"
	"cottendns-go/internal/logger"
	"cottendns-go/internal/security"
	VpnProto "cottendns-go/internal/vpnproto"
)

func newDynamicTransportTestServer(t *testing.T, configuredMethod, method int) (*Server, []byte) {
	t.Helper()
	const sharedKey = "transport-matrix-shared-key"
	preferred, err := security.NewCodec(configuredMethod, sharedKey)
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
		SupportedUploadCompressionTypes:   []int{0, 1, 2, 3},
		SupportedDownloadCompressionTypes: []int{0, 1, 2, 3},
	}, logger.New("transport-matrix-test", "ERROR"), preferred)
	methods := security.AutoDetectMethods(configuredMethod)
	codecSet, err := security.NewCodecSet(methods, sharedKey)
	if err != nil {
		t.Fatal(err)
	}
	preferredIdx := 0
	for i, candidate := range methods {
		if candidate == configuredMethod {
			preferredIdx = i
			break
		}
	}
	s.SetCodecSet(codecSet, preferredIdx)

	changedCodec, err := security.NewCodec(method, sharedKey)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := VpnProto.BuildEncoded(VpnProto.BuildOptions{
		SessionID:  255,
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
	return s, query
}

func assertDynamicMTUResponse(t *testing.T, response []byte) {
	t.Helper()
	packet, err := DnsParser.ExtractVPNResponseMatching(response, false, []string{"v.example.com"})
	if err != nil {
		t.Fatalf("extract dynamic MTU response: %v", err)
	}
	if packet.PacketType != Enums.PACKET_MTU_UP_RES {
		t.Fatalf("dynamic response packet type = %s, want MTU_UP_RES", Enums.PacketTypeName(packet.PacketType))
	}
	if len(packet.Payload) < mtuProbeCodeLength || !bytes.Equal(packet.Payload[:mtuProbeCodeLength], []byte{1, 2, 3, 4}) {
		t.Fatalf("dynamic response verification code = %v, want [1 2 3 4]", packet.Payload)
	}
}

func TestDynamicNativeQueryAcrossAllTransportsAndEncryptionMethods(t *testing.T) {
	profiles := []struct {
		name       string
		configured int
		methods    []int
	}{
		{name: "keyed-server", configured: 1, methods: security.AutoDetectMethods(1)},
		{name: "plaintext-enabled-server", configured: 0, methods: security.AutoDetectMethods(0)},
	}
	for _, profile := range profiles {
		profile := profile
		t.Run(profile.name, func(t *testing.T) {
			for _, method := range profile.methods {
				method := method
				t.Run("method-"+strconv.Itoa(method), func(t *testing.T) {
					t.Run("UDP", func(t *testing.T) {
						s, query := newDynamicTransportTestServer(t, profile.configured, method)
						assertDynamicMTUResponse(t, s.safeHandlePacket(query))
					})

					t.Run("TCP", func(t *testing.T) {
						s, query := newDynamicTransportTestServer(t, profile.configured, method)
						client, server := net.Pipe()
						defer client.Close()
						go func() {
							serveTCPDNSMessages(context.Background(), server, s.safeHandlePacket)
							_ = server.Close()
						}()
						_ = client.SetDeadline(time.Now().Add(3 * time.Second))
						if err := writeTCPDNSMessage(client, query); err != nil {
							t.Fatal(err)
						}
						response, err := readTCPDNSMessage(client)
						if err != nil {
							t.Fatalf("TCP response: %v", err)
						}
						assertDynamicMTUResponse(t, response)
					})

					t.Run("DoT", func(t *testing.T) {
						s, query := newDynamicTransportTestServer(t, profile.configured, method)
						cert, err := generateSelfSignedCert([]string{"v.example.com"})
						if err != nil {
							t.Fatal(err)
						}
						clientRaw, serverRaw := net.Pipe()
						serverTLS := tls.Server(serverRaw, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"dot"}})
						clientTLS := tls.Client(clientRaw, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"dot"}}) // test certificate
						defer clientTLS.Close()
						go func() {
							serveTCPDNSMessages(context.Background(), serverTLS, s.safeHandlePacket)
							_ = serverTLS.Close()
						}()
						_ = clientTLS.SetDeadline(time.Now().Add(3 * time.Second))
						if err := writeTCPDNSMessage(clientTLS, query); err != nil {
							t.Fatal(err)
						}
						response, err := readTCPDNSMessage(clientTLS)
						if err != nil {
							t.Fatalf("DoT response: %v", err)
						}
						assertDynamicMTUResponse(t, response)
						if got := clientTLS.ConnectionState().NegotiatedProtocol; got != "dot" {
							t.Fatalf("DoT ALPN = %q, want dot", got)
						}
					})

					t.Run("DoH", func(t *testing.T) {
						s, query := newDynamicTransportTestServer(t, profile.configured, method)
						req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(query))
						req.Header.Set("Content-Type", dohContentType)
						response := httptest.NewRecorder()
						s.handleDoHRequest(response, req, dohMaxMessageSize)
						if response.Code != http.StatusOK || response.Body.Len() == 0 {
							t.Fatalf("DoH response: status=%d bytes=%d body=%q", response.Code, response.Body.Len(), response.Body.String())
						}
						if got := response.Header().Get("Content-Type"); got != dohContentType {
							t.Fatalf("DoH content type = %q", got)
						}
						assertDynamicMTUResponse(t, response.Body.Bytes())
					})
				})
			}
		})
	}
}
