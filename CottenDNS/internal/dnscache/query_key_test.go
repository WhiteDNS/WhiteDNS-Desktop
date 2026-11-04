package dnscache

import (
	"encoding/binary"
	"path/filepath"
	"testing"
	"time"

	dnsParser "cottendns-go/internal/dnsparser"
)

func TestDNSQueryKeyRetainsPolicyButIgnoresIDAndQNameCase(t *testing.T) {
	query, err := dnsParser.BuildTXTQuestionPacket("example.com", 1, 1232)
	if err != nil {
		t.Fatal(err)
	}
	base := BuildKey("example.com", 1, 1)
	want := BuildQueryKey(query, base)
	identical := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(identical, binary.BigEndian.Uint16(query)+1)
	identical[13] = 'E'
	if got := BuildQueryKey(identical, base); got != want {
		t.Fatal("transaction ID or QNAME case prevented safe coalescing")
	}
	for _, policy := range []string{"cd", "rd", "do", "edns-size", "edns-option"} {
		t.Run(policy, func(t *testing.T) {
			variant := append([]byte(nil), query...)
			switch policy {
			case "cd":
				variant[3] ^= 0x10
			case "rd":
				variant[2] ^= 1
			case "do":
				variant[len(variant)-4] ^= 0x80
			case "edns-size":
				binary.BigEndian.PutUint16(variant[len(variant)-8:len(variant)-6], 1400)
			case "edns-option":
				binary.BigEndian.PutUint16(variant[len(variant)-2:], 4)
				variant = append(variant, 0, 12, 0, 0)
			}
			if BuildQueryKey(variant, base) == want {
				t.Fatal("policy-bearing bytes were excluded from cache/in-flight identity")
			}
		})
	}
}

func TestDNSPolicyKeysSurvivePersistence(t *testing.T) {
	query, err := dnsParser.BuildTXTQuestionPacket("example.com", 1, 1232)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	s := New(128, time.Hour, time.Second)
	keys := make([]string, 3)
	for i := range keys {
		variant := append([]byte(nil), query...)
		if i == 1 {
			variant[3] |= 0x10
		} else if i == 2 {
			variant[len(variant)-4] |= 0x80
		}
		keys[i] = BuildQueryKey(variant, BuildKey("example.com", 1, 1))
		response := cacheAnswer(t, "example.com", 1, 60)
		response[len(response)-1] = byte(i + 1)
		s.SetReady(keys[i], "example.com", 1, 1, response, now)
	}
	path := filepath.Join(t.TempDir(), "dns.cache")
	if count, err := s.SaveToFile(path, now); err != nil || count != len(keys) {
		t.Fatalf("save %d: %v", count, err)
	}
	restored := New(128, time.Hour, time.Second)
	if count, err := restored.LoadFromFile(path, now.Add(time.Second)); err != nil || count != len(keys) {
		t.Fatalf("load %d: %v", count, err)
	}
	for i, key := range keys {
		reply, ok := restored.GetReady(key, query, now.Add(time.Second))
		if !ok || reply[len(reply)-1] != byte(i+1) {
			t.Fatal("binary query policy key lost its independent persisted answer")
		}
	}
}
