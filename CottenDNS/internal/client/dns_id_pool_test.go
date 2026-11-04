package client

import "testing"

func TestDNSIDPoolSkipsActiveAndRetiredIDs(t *testing.T) {
	p := &dnsPendingQueries{byID: make(map[uint16]*dnsPendingGroup)}
	first, ok := p.reserveDNSIDFromStartLocked(42)
	if !ok || first != 42 {
		t.Fatal("free random-start ID was not selected")
	}
	p.byID[first] = &dnsPendingGroup{}
	second, ok := p.reserveDNSIDFromStartLocked(42)
	if !ok || second != 43 {
		t.Fatal("active ID collision was not skipped")
	}
	p.byID[second] = &dnsPendingGroup{}
	delete(p.byID, first)
	third, ok := p.reserveDNSIDFromStartLocked(42)
	if !ok || third != 44 || p.issuedCount != 3 {
		t.Fatal("retired ID was immediately reused")
	}
}

func TestDNSIDPoolScanWrapsWithoutReusingIssuedIDs(t *testing.T) {
	p := &dnsPendingQueries{}
	for _, expected := range []uint16{65535, 0, 1} {
		id, ok := p.reserveDNSIDFromStartLocked(65535)
		if !ok || id != expected {
			t.Fatalf("wrapped ID=%d available=%v, want %d", id, ok, expected)
		}
	}
}

func TestDNSIDPoolFullCycleKeepsActiveAndNewlyRetiredIDsReserved(t *testing.T) {
	p := &dnsPendingQueries{byID: make(map[uint16]*dnsPendingGroup)}
	for i := 0; i < 1<<16; i++ {
		id, ok := p.reserveDNSIDFromStartLocked(uint16(i))
		if !ok || id != uint16(i) {
			t.Fatalf("cycle allocation %d failed", i)
		}
	}
	p.byID[0], p.byID[65535] = &dnsPendingGroup{}, &dnsPendingGroup{}
	id, ok := p.reserveDNSIDFromStartLocked(0)
	if !ok || id != 1 || p.issuedCount != 3 {
		t.Fatal("rollover failed to reserve active IDs and reset issued count")
	}
	delete(p.byID, 0)
	id, ok = p.reserveDNSIDFromStartLocked(0)
	if !ok || id != 2 || p.issuedCount != 4 {
		t.Fatal("an ID active across rollover was reused immediately after retirement")
	}
}

func TestDNSIDPoolExhaustionNeverReusesAnActiveID(t *testing.T) {
	p := &dnsPendingQueries{byID: make(map[uint16]*dnsPendingGroup, 1<<16), issuedCount: 1 << 16}
	for i := range p.issuedIDs {
		p.issuedIDs[i] = ^uint64(0)
	}
	active := &dnsPendingGroup{}
	for i := 0; i < 1<<16; i++ {
		p.byID[uint16(i)] = active
	}
	if _, available := p.reserveDNSIDFromStartLocked(123); available || p.issuedCount != 1<<16 {
		t.Fatal("exhausted pool returned an active ID")
	}
	delete(p.byID, 17)
	if id, available := p.reserveDNSIDFromStartLocked(17); !available || id != 17 || p.issuedCount != 1<<16 {
		t.Fatal("pool did not recover after one ID became free")
	}
}
