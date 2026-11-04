package dnscache

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestDNSCompressedCNAMEAndSOARepliesRemainCacheable(t *testing.T) {
	for _, negative := range []bool{false, true} {
		name := dnsmessage.MustNewName("www.example.com.")
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true})
		b.EnableCompression()
		b.StartQuestions()
		b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
		if negative {
			b.StartAuthorities()
			if err := b.SOAResource(dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("example.com."), Class: dnsmessage.ClassINET, TTL: 120}, dnsmessage.SOAResource{NS: dnsmessage.MustNewName("ns.example.com."), MBox: dnsmessage.MustNewName("hostmaster.example.com."), MinTTL: 60}); err != nil {
				t.Fatal(err)
			}
		} else {
			b.StartAnswers()
			if err := b.CNAMEResource(dnsmessage.ResourceHeader{Name: name, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("target.example.com.")}); err != nil {
				t.Fatal(err)
			}
			if err := b.AResource(dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("target.example.com."), Class: dnsmessage.ClassINET, TTL: 120}, dnsmessage.AResource{A: [4]byte{8, 8, 8, 8}}); err != nil {
				t.Fatal(err)
			}
		}
		wire, err := b.Finish()
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		s := New(128, time.Hour, time.Second)
		key := BuildKey("www.example.com", 1, 1)
		s.SetReady(key, "www.example.com", 1, 1, wire, now)
		reply, ok := s.GetReady(key, nil, now.Add(10*time.Second))
		if !ok {
			t.Fatalf("valid compressed reply rejected, negative=%v", negative)
		}
		var parsed dnsmessage.Message
		if err := parsed.Unpack(reply); err != nil {
			t.Fatal(err)
		}
		if answerTTL(t, reply) != 50 {
			t.Fatal("compressed reply TTL did not age against the minimum lifetime")
		}
		if _, ok = s.GetReady(key, nil, now.Add(time.Minute)); ok {
			t.Fatal("compressed reply outlived its minimum TTL")
		}
	}
}

func TestDNSPersistenceFailureLeavesLiveCacheAndRetryIntact(t *testing.T) {
	now := time.Now()
	s := New(128, time.Hour, time.Second)
	key := BuildKey("example.com", 1, 1)
	s.SetReady(key, "example.com", 1, 1, cacheAnswer(t, "example.com", 1, 60), now)
	directory := t.TempDir()
	blocker := filepath.Join(directory, "file-as-directory")
	if err := os.WriteFile(blocker, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveToFile(filepath.Join(blocker, "dns.cache"), now); err == nil {
		t.Fatal("expected failed disk write")
	}
	if _, ok := s.GetReady(key, nil, now.Add(5*time.Second)); !ok {
		t.Fatal("disk failure removed a usable cached answer")
	}
	valid := filepath.Join(directory, "dns.cache")
	if count, err := s.SaveToFile(valid, now.Add(5*time.Second)); err != nil || count != 1 {
		t.Fatalf("save retry lost dirty state: count=%d err=%v", count, err)
	}
	corrupt := filepath.Join(directory, "corrupt.cache")
	if err := os.WriteFile(corrupt, []byte{0x44, 0x4e, 0x53, 0x43, 0, 2, 0, 0, 0, 1, 0}, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadFromFile(corrupt, now.Add(5*time.Second)); err == nil {
		t.Fatal("expected malformed cache file rejection")
	}
	if _, ok := s.GetReady(key, nil, now.Add(5*time.Second)); !ok {
		t.Fatal("failed load damaged the existing cache")
	}
	loaded := New(128, 20*time.Second, time.Second)
	if count, err := loaded.LoadFromFile(valid, now.Add(10*time.Second)); err != nil || count != 1 {
		t.Fatalf("load %d: %v", count, err)
	}
	query := []byte{0x12, 0x34, 0x01, 0x10}
	reply, ok := loaded.GetReady(key, query, now.Add(10*time.Second))
	if !ok || answerTTL(t, reply) != 10 || binary.BigEndian.Uint16(reply[:2]) != 0x1234 {
		t.Fatal("reload ignored the shorter cache cap or lost query transaction ID")
	}
}
