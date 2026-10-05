package udpserver

import (
	"encoding/binary"
	"strings"
	"testing"

	DnsParser "cottendns-go/internal/dnsparser"
	Enums "cottendns-go/internal/enums"
)

func TestZoneNSDropsInZoneNames(t *testing.T) {
	got := outOfZoneNameservers([]string{"v.example.com"}, []string{"NS.Example.com.", "ns.v.example.com", "v.example.com", "localhost", " ns2.other.net "})
	if strings.Join(got, ",") != "ns.example.com,ns2.other.net" {
		t.Fatalf("got %v", got)
	}
}

func TestApexNSAnsweredOnlyWhenConfigured(t *testing.T) {
	const zone = "v.example.com"
	query := apexQuery(t, zone, Enums.DNS_RECORD_TYPE_NS)
	parsed, err := DnsParser.ParseDNSRequestLite(query)
	if err != nil {
		t.Fatal(err)
	}
	answers := func(s *Server) uint16 {
		resp := s.zoneNoDataResponse(query, parsed, zone)
		if len(resp) < 12 {
			t.Fatal("no response")
		}
		return binary.BigEndian.Uint16(resp[6:8])
	}
	if n := answers(&Server{}); n != 0 {
		t.Fatalf("unconfigured server answered NS with %d records", n)
	}
	if n := answers(&Server{zoneNS: []string{"ns.example.com"}}); n != 1 {
		t.Fatalf("configured server answered NS with %d records, want 1", n)
	}
}

func apexQuery(t *testing.T, name string, qtype uint16) []byte {
	t.Helper()
	q := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(name, ".") {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0)
	q = binary.BigEndian.AppendUint16(q, qtype)
	return binary.BigEndian.AppendUint16(q, Enums.DNSQ_CLASS_IN)
}
