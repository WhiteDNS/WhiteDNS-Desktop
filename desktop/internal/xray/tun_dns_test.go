package xray

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"whitedns-desktop/internal/model"
)

// Run the bundled core's complete DNS routing path without an OS TUN device.
// A UDP test inbound stands in for packets from TUN; a TCP-only SOCKS server
// fails any UDP ASSOCIATE and returns deterministic DNS responses. No Internet
// access, elevated privileges, or machine DNS settings are used.
func TestBundledTunDNSUsesTCPAndCachesAnswers(t *testing.T) {
	core := os.Getenv("WHITEDNS_XRAY_TEST_BIN")
	if core == "" {
		t.Skip("bundled core not supplied")
	}
	socks, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socks.Close()
	var queries, unsupported atomic.Int32
	go func() {
		for {
			c, e := socks.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				var greeting [3]byte
				if _, e := io.ReadFull(c, greeting[:]); e != nil {
					return
				}
				_, _ = c.Write([]byte{5, 0})
				var head [4]byte
				if _, e := io.ReadFull(c, head[:]); e != nil {
					return
				}
				if head[1] != 1 {
					unsupported.Add(1)
					return
				}
				n := 4
				switch head[3] {
				case 1:
				case 4:
					n = 16
				case 3:
					var length [1]byte
					if _, e := io.ReadFull(c, length[:]); e != nil {
						return
					}
					n = int(length[0])
				default:
					return
				}
				if _, e := io.ReadFull(c, make([]byte, n+2)); e != nil {
					return
				}
				_, _ = c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
				for {
					var length uint16
					if binary.Read(c, binary.BigEndian, &length) != nil {
						return
					}
					raw := make([]byte, int(length))
					if _, e := io.ReadFull(c, raw); e != nil {
						return
					}
					var message dnsmessage.Message
					if message.Unpack(raw) != nil || len(message.Questions) != 1 {
						return
					}
					queries.Add(1)
					q := message.Questions[0]
					message.Header.Response = true
					message.Header.RecursionAvailable = true
					header := dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: dnsmessage.ClassINET, TTL: 60}
					if q.Type == dnsmessage.TypeA {
						message.Answers = []dnsmessage.Resource{{Header: header, Body: &dnsmessage.AResource{A: [4]byte{203, 0, 113, 10}}}}
					} else {
						message.Answers = []dnsmessage.Resource{{Header: header, Body: &dnsmessage.TXTResource{TXT: []string{"tcp-tunnel"}}}}
					}
					raw, e := message.Pack()
					if e != nil {
						return
					}
					_ = binary.Write(c, binary.BigEndian, uint16(len(raw)))
					if _, e = c.Write(raw); e != nil {
						return
					}
				}
			}()
		}
	}()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := udp.LocalAddr().(*net.UDPAddr).Port
	udp.Close()
	settings := model.DefaultSoarSettingsProfile()
	settings.StormDNSListenPort = socks.Addr().(*net.TCPAddr).Port
	raw, err := RenderDNSConfigWithTun(settings)
	if err != nil {
		t.Fatal(err)
	}
	config := decodeConfig(t, raw)
	config["inbounds"] = []any{map[string]any{"protocol": "dokodemo-door", "listen": "127.0.0.1", "port": port, "tag": TunInboundTag, "settings": map[string]any{"address": "198.18.0.2", "port": 53, "network": "udp"}}}
	// Deterministic DNS upstream; the production config uses tunneled DoH.
	config["dns"].(map[string]any)["servers"] = []string{"tcp://198.51.100.53"}
	data, _ := json.Marshal(config)
	file := filepath.Join(t.TempDir(), "dns-test.json")
	if e := os.WriteFile(file, data, 0600); e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(core, "run", "-c", file)
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	request := func(kind dnsmessage.Type) dnsmessage.Message {
		t.Helper()
		name, _ := dnsmessage.NewName("test.example.")
		question := dnsmessage.Message{Header: dnsmessage.Header{ID: 1234, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: kind, Class: dnsmessage.ClassINET}}}
		packet, _ := question.Pack()
		conn, e := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
		if e != nil {
			t.Fatal(e)
		}
		defer conn.Close()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			_ = conn.SetDeadline(time.Now().Add(200 * time.Millisecond))
			_, _ = conn.Write(packet)
			buffer := make([]byte, 1500)
			n, e := conn.Read(buffer)
			if e != nil {
				continue
			}
			var reply dnsmessage.Message
			if reply.Unpack(buffer[:n]) != nil || reply.Header.ID != 1234 || len(reply.Answers) != 1 {
				t.Fatal("invalid tunnel DNS response")
			}
			return reply
		}
		t.Fatal("UDP DNS request did not return through TCP SOCKS")
		return dnsmessage.Message{}
	}
	reply := request(dnsmessage.TypeA)
	if answer, ok := reply.Answers[0].Body.(*dnsmessage.AResource); !ok || answer.A != [4]byte{203, 0, 113, 10} {
		t.Fatal("DNS answer changed")
	}
	before := queries.Load()
	request(dnsmessage.TypeA)
	if queries.Load() != before {
		t.Fatal("repeated DNS lookup missed the tunnel cache")
	}
	request(dnsmessage.TypeTXT)
	if unsupported.Load() != 0 {
		t.Fatal("unsupported UDP ASSOCIATE reached the engine")
	}
}
