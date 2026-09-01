package udpserver

import (
	"net"
	"testing"
	"time"
)

func TestClientIPLimitKeyGroupsIPv6ByPrefix(t *testing.T) {
	a := clientIPLimitKey("2001:db8:1234:5678::1")
	b := clientIPLimitKey("2001:db8:1234:5678:ffff::99")
	c := clientIPLimitKey("2001:db8:1234:5679::1")
	if a != "2001:db8:1234:5678::/64" || b != a {
		t.Fatalf("same /64 keys = %q and %q", a, b)
	}
	if c == a {
		t.Fatalf("different /64 unexpectedly shared key %q", c)
	}
	if got := clientIPLimitKey("::ffff:192.0.2.10"); got != "192.0.2.10" {
		t.Fatalf("IPv4-mapped key = %q", got)
	}
}

func TestTCPRemoteIPKeyGroupsIPv6PrivacyAddresses(t *testing.T) {
	a := tcpRemoteIPKey(&net.TCPAddr{IP: net.ParseIP("2001:db8:abcd:1::1"), Port: 1000})
	b := tcpRemoteIPKey(&net.TCPAddr{IP: net.ParseIP("2001:db8:abcd:1::ffff"), Port: 2000})
	if a != b || a != "2001:db8:abcd:1::/64" {
		t.Fatalf("TCP IPv6 keys = %q and %q", a, b)
	}
}

func TestDoHRateLimiterCannotBypassWithIPv6AddressRotation(t *testing.T) {
	limiter := newDoHRateLimiter(1, 1)
	now := time.Unix(100, 0)
	if !limiter.allow("2001:db8:1:2::1", now) {
		t.Fatal("first address should consume the /64 token")
	}
	if limiter.allow("2001:db8:1:2::2", now) {
		t.Fatal("second address in the same /64 bypassed the rate limit")
	}
	if !limiter.allow("2001:db8:1:3::1", now) {
		t.Fatal("a different /64 should have an independent token")
	}
}

func TestDoHRateLimiterStateIsBounded(t *testing.T) {
	limiter := newDoHRateLimiter(1, 1)
	now := time.Unix(100, 0)
	for i := 0; i < maxDoHRateLimiterStates; i++ {
		key := net.IP{0x20, 0x01, 0x0d, 0xb8, byte(i >> 8), byte(i), 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}.String()
		if !limiter.allow(key, now) {
			t.Fatalf("identity %d rejected before state ceiling", i)
		}
	}
	if limiter.allow("2001:db8:ffff::1", now) {
		t.Fatal("new identity admitted after state ceiling")
	}
	if got := len(limiter.states); got != maxDoHRateLimiterStates {
		t.Fatalf("state count = %d, want %d", got, maxDoHRateLimiterStates)
	}
}

func TestInvalidCookieTrackerStateIsBounded(t *testing.T) {
	tracker := newInvalidCookieTracker()
	lookup := sessionLookupResult{State: sessionLookupActive, Cookie: 7}
	for i := 0; i < maxInvalidCookieTrackerRecords; i++ {
		tracker.Note(uint16(i), lookup, true, uint8(i), 100, int64(time.Second), 10)
	}
	tracker.Note(uint16(maxInvalidCookieTrackerRecords+1), lookup, true, 99, 100, int64(time.Second), 10)
	if got := len(tracker.records); got != maxInvalidCookieTrackerRecords {
		t.Fatalf("invalid-cookie state count = %d, want %d", got, maxInvalidCookieTrackerRecords)
	}
}
