package client

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"cottendns-go/internal/config"
	DnsParser "cottendns-go/internal/dnsparser"
	Enums "cottendns-go/internal/enums"
)

func TestAuthoritativeControlResponsesDoNotDeliverTunnelData(t *testing.T) {
	for _, qType := range []uint16{Enums.DNS_RECORD_TYPE_A, Enums.DNS_RECORD_TYPE_AAAA} {
		for _, refused := range []bool{false, true} {
			name := Enums.DNSRecordTypeName(qType) + "/NODATA"
			if refused {
				name = Enums.DNSRecordTypeName(qType) + "/REFUSED"
			}
			t.Run(name, func(t *testing.T) {
				c := buildTestClientWithResolvers(config.ClientConfig{
					Domains:                         []string{"example.com"},
					ResolverIgnoreInjectedNXDOMAIN:  true,
					AutoDisableTimeoutServers:       true,
					AutoDisableTimeoutWindowSeconds: 90,
					TunnelPacketTimeoutSec:          10,
				}, "a", "b", "c", "d")
				c.initResolverRecheckMeta()
				addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5300}
				query, err := DnsParser.BuildTXTQuestionPacket("probe.example.com", qType, 0)
				if err != nil {
					t.Fatal(err)
				}
				const id uint16 = 4242
				binary.BigEndian.PutUint16(query[:2], id)
				parsed, err := DnsParser.ParseDNSRequestLite(query)
				if err != nil {
					t.Fatal(err)
				}
				var response []byte
				if refused {
					response, err = DnsParser.BuildRefusedResponseFromLite(query, parsed)
				} else {
					response, err = DnsParser.BuildAuthoritativeNoDataFromLite(query, parsed, "example.com")
				}
				if err != nil {
					t.Fatal(err)
				}
				key := resolverSampleKey{resolverAddr: addr.String(), dnsID: id}
				c.resolverPending[key] = resolverSample{serverKey: "a", sentAt: time.Now()}
				c.handleInboundPacket(response, addr, "")
				c.resolverStatsMu.Lock()
				_, pending := c.resolverPending[key]
				c.resolverStatsMu.Unlock()
				if pending == refused {
					t.Fatalf("pending=%v; REFUSED must record failure, NODATA must await tunnel response", pending)
				}
				wantEvents := 0
				if refused {
					wantEvents = 1
				}
				if events, success := resolverHealthEventCount(c, "a"); events != wantEvents || !success.IsZero() {
					t.Fatalf("unexpected resolver scoring: events=%d success=%v", events, success)
				}
				for i := range c.carrier.success {
					if got := c.carrier.success[i].Load(); got != 0 {
						t.Fatalf("control reply credited carrier %d success: %d", i, got)
					}
				}
				if got := c.injectedNXDOMAINCount.Load(); got != 0 {
					t.Fatalf("control reply treated as NXDOMAIN: %d", got)
				}
			})
		}
	}
}
