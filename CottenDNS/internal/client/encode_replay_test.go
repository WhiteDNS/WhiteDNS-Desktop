package client

import (
	"context"
	"strings"
	"testing"
	"time"

	DnsParser "cottendns-go/internal/dnsparser"
	Enums "cottendns-go/internal/enums"
	"cottendns-go/internal/security"
	VpnProto "cottendns-go/internal/vpnproto"
)

func TestEncodeFanoutUsesFreshCiphertextForDifferentQuestions(t *testing.T) {
	c := createTestClient(t)
	c.codec, _ = security.NewCodec(5, "fanout-test")
	c.carrier = nil
	c.queryTypes = []uint16{Enums.DNS_RECORD_TYPE_TXT, Enums.DNS_RECORD_TYPE_CNAME}
	conns := []Connection{
		{Domain: "example.com", Resolver: "127.0.0.1", ResolverPort: 5300},
		{Domain: "example.com", Resolver: "127.0.0.2", ResolverPort: 5300},
		{Domain: "example.net", Resolver: "127.0.0.3", ResolverPort: 5300},
		{Domain: "example.com", Resolver: "127.0.0.4", ResolverPort: 5300},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); c.asyncWG.Wait() }()
	c.asyncWG.Add(1)
	go c.asyncEncodeWorker(ctx, 0)
	c.txChannel <- rawOutboundTask{wasPacked: true, packetType: Enums.PACKET_PING, opts: VpnProto.BuildOptions{SessionID: 300, SessionCookie: 7, PacketType: Enums.PACKET_PING, Payload: []byte("fanout")}, conns: conns}
	select {
	case task := <-c.encodedTXChannel:
		if len(task.frames) != 4 {
			t.Fatalf("frames=%d", len(task.frames))
		}
		labels := make([]string, 4)
		for i, frame := range task.frames {
			p, err := DnsParser.ParsePacket(frame.packet)
			if err != nil {
				t.Fatal(err)
			}
			labels[i] = strings.ReplaceAll(strings.TrimSuffix(strings.TrimSuffix(p.Questions[0].Name, "."), "."+conns[i].Domain), ".", "")
			decoded, err := VpnProto.ParseFromLabels(labels[i], c.codec)
			if err != nil || string(decoded.Payload) != "fanout" {
				t.Fatalf("frame %d: %v", i, err)
			}
		}
		if labels[0] == labels[1] || labels[0] == labels[2] || labels[1] == labels[2] {
			t.Fatal("different questions reused authenticated ciphertext")
		}
		if labels[1] != labels[3] {
			t.Fatal("identical retry query was not reused")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("encode worker stalled")
	}
}
