package dnscache

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func cacheAnswer(t *testing.T, domain string, kind uint16, ttl uint32) []byte {
	t.Helper()
	name, err := dnsmessage.NewName(domain + ".")
	if err != nil {
		t.Fatal(err)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7, Response: true, RecursionAvailable: true})
	if err = b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err = b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.Type(kind), Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	if err = b.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	h := dnsmessage.ResourceHeader{Name: name, Class: dnsmessage.ClassINET, TTL: ttl}
	if kind == 28 {
		err = b.AAAAResource(h, dnsmessage.AAAAResource{AAAA: [16]byte{0x20, 1, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88}})
	} else {
		err = b.AResource(h, dnsmessage.AResource{A: [4]byte{8, 8, 8, 8}})
	}
	if err != nil {
		t.Fatal(err)
	}
	wire, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func cacheNegative(t *testing.T, ttl, minimum uint32) []byte {
	t.Helper()
	name := dnsmessage.MustNewName("example.com.")
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, RCode: dnsmessage.RCodeNameError})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	b.StartAuthorities()
	err := b.SOAResource(dnsmessage.ResourceHeader{Name: name, Class: dnsmessage.ClassINET, TTL: ttl}, dnsmessage.SOAResource{NS: dnsmessage.MustNewName("ns.example.com."), MBox: dnsmessage.MustNewName("hostmaster.example.com."), MinTTL: minimum})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func answerTTL(t *testing.T, wire []byte) uint32 {
	t.Helper()
	var message dnsmessage.Message
	if err := message.Unpack(wire); err != nil {
		t.Fatal(err)
	}
	if len(message.Answers) != 0 {
		return message.Answers[0].Header.TTL
	}
	if len(message.Authorities) != 0 {
		return message.Authorities[0].Header.TTL
	}
	t.Fatal("missing cached resource")
	return 0
}

func TestDNSExpiryDoesNotSlideAndRepliesAge(t *testing.T) {
	now := time.Now()
	s := New(128, 4*time.Hour, time.Second)
	key := BuildKey("example.com", 1, 1)
	s.SetReady(key, "example.com", 1, 1, cacheAnswer(t, "example.com", 1, 60), now)
	for i := 1; i < 60; i++ {
		result := s.LookupOrCreatePending(key, "example.com", 1, 1, now.Add(time.Duration(i)*time.Second))
		if result.Status != StatusReady || answerTTL(t, result.Response) != uint32(60-i) {
			t.Fatalf("TTL at second %d did not age", i)
		}
		result.Response[0] = 255 // callers must not mutate the stored response
	}
	if _, hit := s.GetReady(key, nil, now.Add(time.Minute)); hit {
		t.Fatal("hot DNS answer survived its absolute TTL")
	}
	if _, hit := s.GetReady(key, nil, now.Add(72*time.Hour)); hit {
		t.Fatal("old answer revived after 72 hours")
	}
}

func TestDNSPersistencePreservesExpiryAndReceiptTime(t *testing.T) {
	now := time.Now()
	key := BuildKey("example.com", 1, 1)
	s := New(128, time.Hour, time.Second)
	s.SetReady(key, "example.com", 1, 1, cacheAnswer(t, "example.com", 1, 60), now)
	s.GetReady(key, nil, now.Add(50*time.Second))
	path := filepath.Join(t.TempDir(), "nested", "dns.cache")
	if count, err := s.SaveToFile(path, now.Add(50*time.Second)); err != nil || count != 1 {
		t.Fatalf("save %d: %v", count, err)
	}
	restored := New(128, time.Hour, time.Second)
	if count, err := restored.LoadFromFile(path, now.Add(55*time.Second)); err != nil || count != 1 {
		t.Fatalf("load %d: %v", count, err)
	}
	response, ok := restored.GetReady(key, nil, now.Add(55*time.Second))
	if !ok || answerTTL(t, response) != 5 {
		t.Fatal("restart renewed the cached TTL")
	}
	if _, ok = restored.GetReady(key, nil, now.Add(time.Minute)); ok {
		t.Fatal("restart extended absolute expiration")
	}
	legacy := filepath.Join(t.TempDir(), "v1.cache")
	if err := os.WriteFile(legacy, []byte{0x44, 0x4e, 0x53, 0x43, 0, 1, 0, 0, 0, 0}, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := restored.LoadFromFile(legacy, now); err == nil {
		t.Fatal("legacy sliding-expiry cache was trusted")
	}
}

func TestDNSConfiguredCapAndFreshReplacement(t *testing.T) {
	now := time.Now()
	key := BuildKey("example.com", 1, 1)
	s := New(128, 10*time.Second, time.Second)
	s.SetReady(key, "example.com", 1, 1, cacheAnswer(t, "example.com", 1, 60), now)
	response, _ := s.GetReady(key, nil, now.Add(time.Second))
	if answerTTL(t, response) != 9 {
		t.Fatal("configured cache cap not applied to reply TTL")
	}
	s.SetReady(key, "example.com", 1, 1, cacheAnswer(t, "example.com", 1, 60), now.Add(5*time.Second))
	if _, ok := s.GetReady(key, nil, now.Add(11*time.Second)); !ok {
		t.Fatal("fresh answer inherited the old receipt time")
	}
	if _, ok := s.GetReady(key, nil, now.Add(15*time.Second)); ok {
		t.Fatal("replacement survived its configured lifetime")
	}
}

func TestDNSNegativeSOALifetimeAndOPTFlags(t *testing.T) {
	now := time.Now()
	key := BuildKey("example.com", 1, 1)
	s := New(128, time.Hour, time.Second)
	s.SetReady(key, "example.com", 1, 1, cacheNegative(t, 60, 5), now)
	response, ok := s.GetReady(key, nil, now.Add(3*time.Second))
	if !ok || answerTTL(t, response) != 2 {
		t.Fatal("negative SOA MINIMUM was not enforced")
	}
	if _, ok = s.GetReady(key, nil, now.Add(5*time.Second)); ok {
		t.Fatal("negative answer exceeded SOA lifetime")
	}
	positive := cacheAnswer(t, "example.com", 1, 60)
	binary.BigEndian.PutUint16(positive[10:12], 1)
	positive = append(positive, 0, 0, 41, 4, 208, 0, 0, 0x80, 0, 0, 0)
	s.SetReady(key, "example.com", 1, 1, positive, now)
	response, ok = s.GetReady(key, nil, now.Add(3*time.Second))
	if !ok || binary.BigEndian.Uint32(response[len(response)-6:len(response)-2]) != 0x8000 {
		t.Fatal("EDNS flags were aged as a TTL")
	}
}

func TestDNSRejectsTransientAndInvalidAnswers(t *testing.T) {
	for _, scenario := range []string{"servfail", "refused", "truncated", "zero-ttl", "request", "wrong-question", "malformed", "negative-no-soa"} {
		t.Run(scenario, func(t *testing.T) {
			now := time.Now()
			s := New(128, time.Hour, time.Second)
			key := BuildKey("example.com", 1, 1)
			s.LookupOrCreatePending(key, "example.com", 1, 1, now)
			wire := cacheAnswer(t, "example.com", 1, 60)
			switch scenario {
			case "servfail":
				wire[3] = 2
			case "refused":
				wire[3] = 5
			case "truncated":
				wire[2] |= 2
			case "zero-ttl":
				wire = cacheAnswer(t, "example.com", 1, 0)
			case "request":
				wire[2] &^= 0x80
			case "wrong-question":
				wire = cacheAnswer(t, "different.example", 1, 60)
			case "malformed":
				wire = wire[:len(wire)-1]
			case "negative-no-soa":
				wire[3] = 3
			}
			s.SetReady(key, "example.com", 1, 1, wire, now)
			if _, ok := s.GetReady(key, nil, now); ok || s.HasPending() {
				t.Fatal("invalid reply was retained or left pending")
			}
		})
	}
}

func TestDNSSaveSnapshotDuringUpdates(t *testing.T) {
	s := New(1024, time.Hour, time.Second)
	now := time.Now()
	answers := make([][]byte, 64)
	for i := range answers {
		answers[i] = cacheAnswer(t, fmt.Sprintf("d%d.example", i), 1, 60)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			domain := fmt.Sprintf("d%d.example", i%len(answers))
			s.SetReady(BuildKey(domain, 1, 1), domain, 1, 1, answers[i%len(answers)], now)
		}
	}()
	path := filepath.Join(t.TempDir(), "dns.cache")
	for i := 0; i < 20; i++ {
		if _, err := s.SaveToFile(path, now); err != nil {
			t.Fatal(err)
		}
		if _, err := New(1024, time.Hour, time.Second).LoadFromFile(path, now); err != nil {
			t.Fatal("inconsistent snapshot", err)
		}
	}
	wg.Wait()
}
