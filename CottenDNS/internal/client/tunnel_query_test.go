// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================

package client

import (
	"sync"
	"testing"

	Enums "cottendns-go/internal/enums"
)

func TestNextQueryTypeDefaultsToTXT(t *testing.T) {
	// Nil client and empty set both fall back to TXT (historical behavior).
	var nilClient *Client
	if got := nilClient.nextQueryType(); got != Enums.DNS_RECORD_TYPE_TXT {
		t.Fatalf("nil client: got %d, want TXT(%d)", got, Enums.DNS_RECORD_TYPE_TXT)
	}

	empty := &Client{}
	if got := empty.nextQueryType(); got != Enums.DNS_RECORD_TYPE_TXT {
		t.Fatalf("empty set: got %d, want TXT(%d)", got, Enums.DNS_RECORD_TYPE_TXT)
	}
}

func TestNextQueryTypeSingleAlwaysReturnsThatType(t *testing.T) {
	c := &Client{queryTypes: []uint16{Enums.DNS_RECORD_TYPE_CNAME}}
	for i := 0; i < 5; i++ {
		if got := c.nextQueryType(); got != Enums.DNS_RECORD_TYPE_CNAME {
			t.Fatalf("iteration %d: got %d, want CNAME(%d)", i, got, Enums.DNS_RECORD_TYPE_CNAME)
		}
	}
}

func TestNextQueryTypeRotatesRoundRobin(t *testing.T) {
	set := []uint16{
		Enums.DNS_RECORD_TYPE_TXT,
		Enums.DNS_RECORD_TYPE_CNAME,
		Enums.DNS_RECORD_TYPE_A,
	}
	c := &Client{queryTypes: set}

	// Two full cycles should reproduce the set order exactly.
	for cycle := 0; cycle < 2; cycle++ {
		for i, want := range set {
			if got := c.nextQueryType(); got != want {
				t.Fatalf("cycle %d index %d: got %d, want %d", cycle, i, got, want)
			}
		}
	}
}

func TestNextQueryTypeConcurrentCoversWholeSet(t *testing.T) {
	set := []uint16{
		Enums.DNS_RECORD_TYPE_TXT,
		Enums.DNS_RECORD_TYPE_CNAME,
		Enums.DNS_RECORD_TYPE_A,
		Enums.DNS_RECORD_TYPE_AAAA,
	}
	c := &Client{queryTypes: set}

	const goroutines = 16
	const perGoroutine = 1000
	counts := make([]int, len(set))
	var mu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(goroutines)
	codeIndex := map[uint16]int{}
	for i, code := range set {
		codeIndex[code] = i
	}

	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			local := make([]int, len(set))
			for i := 0; i < perGoroutine; i++ {
				code := c.nextQueryType()
				idx, ok := codeIndex[code]
				if !ok {
					t.Errorf("unexpected qType %d", code)
					return
				}
				local[idx]++
			}
			mu.Lock()
			for i := range local {
				counts[i] += local[i]
			}
			mu.Unlock()
		}()
	}
	wg.Wait()

	// With round-robin over an atomic cursor, totals must be perfectly even.
	want := goroutines * perGoroutine / len(set)
	for i, c := range counts {
		if c != want {
			t.Fatalf("qType index %d selected %d times, want %d (even split)", i, c, want)
		}
	}
}

func TestMTUProbeQueryTypesPreferBulkCarriers(t *testing.T) {
	c := &Client{queryTypes: []uint16{
		Enums.DNS_RECORD_TYPE_CNAME, Enums.DNS_RECORD_TYPE_TXT, Enums.DNS_RECORD_TYPE_HTTPS, Enums.DNS_RECORD_TYPE_A,
	}}
	want := []uint16{Enums.DNS_RECORD_TYPE_TXT, Enums.DNS_RECORD_TYPE_HTTPS, Enums.DNS_RECORD_TYPE_CNAME, Enums.DNS_RECORD_TYPE_A}
	got := c.mtuProbeQueryTypes(true)
	if len(got) != len(want) {
		t.Fatalf("download probes lost a carrier: %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("download probes must try bulk carriers before small fallbacks: got %v want %v", got, want)
		}
	}
	var nilClient *Client
	for _, empty := range []*Client{nilClient, {}} {
		if got := empty.mtuProbeQueryTypes(true); len(got) != 1 || got[0] != Enums.DNS_RECORD_TYPE_TXT {
			t.Fatalf("empty configuration should probe TXT: %v", got)
		}
	}
}
