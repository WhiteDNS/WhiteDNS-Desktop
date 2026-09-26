package client

import (
	"testing"
	"time"

	Enums "cottendns-go/internal/enums"
)

func TestCarrierSelector_SingleTypeIsPassthrough(t *testing.T) {
	s := newCarrierSelector([]uint16{Enums.DNS_RECORD_TYPE_TXT}, nil)
	for i := 0; i < 10; i++ {
		if got := s.next(); got != Enums.DNS_RECORD_TYPE_TXT {
			t.Fatalf("single-type selector must always return TXT, got %d", got)
		}
	}
}

// A carrier whose responses stop coming back (blocked/poisoned) is dropped from
// rotation, the working carrier stays, and the dropped one is re-explored later.
func TestCarrierSelector_DropsBlockedCarrierAndReexplores(t *testing.T) {
	now := time.Now()
	s := newCarrierSelector(
		[]uint16{Enums.DNS_RECORD_TYPE_TXT, Enums.DNS_RECORD_TYPE_CNAME},
		func() time.Time { return now },
	)
	txt := uint16(Enums.DNS_RECORD_TYPE_TXT)
	cname := uint16(Enums.DNS_RECORD_TYPE_CNAME)

	// send n queries; TXT always answers, CNAME never does (blocked).
	send := func(n int) map[uint16]int {
		counts := map[uint16]int{}
		for i := 0; i < n; i++ {
			qt := s.next()
			counts[qt]++
			if qt == txt {
				s.recordSuccess(txt)
			}
		}
		return counts
	}

	send(200) // ~100 each, enough to exceed carrierMinSamples

	// Trigger an eval.
	now = now.Add(carrierEvalInterval + time.Second)
	counts := send(100)
	if counts[txt] == 0 {
		t.Fatal("working TXT carrier must stay in rotation")
	}
	if counts[cname] > counts[txt]/4 {
		t.Fatalf("blocked CNAME should be largely dropped: txt=%d cname=%d", counts[txt], counts[cname])
	}

	// Re-exploration: with ongoing TXT traffic, CNAME's send count decays until it
	// drops below carrierMinSamples and re-enters rotation for a retry.
	reappeared := false
	for k := 0; k < 10 && !reappeared; k++ {
		now = now.Add(carrierEvalInterval + time.Second)
		send(10)
		for _, ti := range *s.active.Load() {
			if s.types[ti] == cname {
				reappeared = true
			}
		}
	}
	if !reappeared {
		t.Fatal("dropped carrier should be re-explored after decay")
	}
}

func TestCarrierSelector_IsolatesBlockedCarrierByPath(t *testing.T) {
	now := time.Now()
	s := newCarrierSelector([]uint16{Enums.DNS_RECORD_TYPE_TXT, Enums.DNS_RECORD_TYPE_CNAME}, func() time.Time { return now })
	for i := 0; i < 200; i++ {
		if qt := s.nextForPath("blocked"); qt == Enums.DNS_RECORD_TYPE_TXT {
			s.recordSuccessForPath("blocked", qt)
		}
		qt := s.nextForPath("clean")
		s.recordSuccessForPath("clean", qt)
	}
	now = now.Add(carrierEvalInterval + time.Second)
	blockedCNAME, cleanCNAME := 0, 0
	for i := 0; i < 100; i++ {
		if s.nextForPath("blocked") == Enums.DNS_RECORD_TYPE_CNAME {
			blockedCNAME++
		}
		if s.nextForPath("clean") == Enums.DNS_RECORD_TYPE_CNAME {
			cleanCNAME++
		}
	}
	if blockedCNAME >= cleanCNAME/2 {
		t.Fatalf("blocked carrier leaked across path scores: blocked=%d clean=%d", blockedCNAME, cleanCNAME)
	}
}

func TestCarrierSelector_PathSendCreditsActualCarrier(t *testing.T) {
	now := time.Now()
	s := newCarrierSelector([]uint16{Enums.DNS_RECORD_TYPE_TXT, Enums.DNS_RECORD_TYPE_CNAME}, func() time.Time { return now })
	path := s.forPath("cname-only")
	// The resolver's working carrier differs from the aggregate's choice.
	globalActive, pathActive := []int{0}, []int{1}
	s.active.Store(&globalActive)
	path.active.Store(&pathActive)
	s.lastEvalNano.Store(now.UnixNano())
	path.lastEvalNano.Store(now.UnixNano())
	for range 5 {
		qType := s.nextForPath("cname-only")
		if qType != Enums.DNS_RECORD_TYPE_CNAME {
			t.Fatalf("path carrier=%d, want CNAME", qType)
		}
		s.recordSuccessForPath("cname-only", qType)
	}
	if s.sent[0].Load() != 0 || s.sent[1].Load() != 5 || s.success[1].Load() != 5 {
		t.Fatalf("aggregate counts don't match actual sends: TXT=%d CNAME=%d success=%d", s.sent[0].Load(), s.sent[1].Load(), s.success[1].Load())
	}
}

func TestCarrierSelector_PollsPreferBulkAndPreserveControlRotation(t *testing.T) {
	s := newCarrierSelector([]uint16{Enums.DNS_RECORD_TYPE_TXT, Enums.DNS_RECORD_TYPE_CNAME, Enums.DNS_RECORD_TYPE_NULL, Enums.DNS_RECORD_TYPE_A}, nil)
	polls, control := map[uint16]int{}, map[uint16]int{}
	for range 100 {
		qt := s.nextForPathWithPreference("working", true)
		polls[qt]++
		s.recordSuccessForPath("working", qt)
		qt = s.nextForPath("working")
		control[qt]++
		s.recordSuccessForPath("working", qt)
	}
	if len(polls) != 2 || polls[Enums.DNS_RECORD_TYPE_TXT] != 50 || polls[Enums.DNS_RECORD_TYPE_NULL] != 50 {
		t.Fatalf("polls must fairly drain both bulk carriers: %v", polls)
	}
	if len(control) != 4 {
		t.Fatalf("normal traffic must still explore every carrier: %v", control)
	}
}

func TestCarrierSelector_PollFallbackReexploresRecoveredBulk(t *testing.T) {
	now := time.Now()
	s := newCarrierSelector([]uint16{Enums.DNS_RECORD_TYPE_TXT, Enums.DNS_RECORD_TYPE_CNAME}, func() time.Time { return now })
	// Bulk replies are blocked while CNAME stays reachable.
	for range 100 {
		s.nextForPathWithPreference("path", true)
	}
	now = now.Add(carrierEvalInterval + time.Second)
	for range 30 {
		qt := s.nextForPathWithPreference("path", true)
		if qt != Enums.DNS_RECORD_TYPE_CNAME {
			t.Fatalf("all failed bulk carriers must fall back to CNAME, got %d", qt)
		}
		s.recordSuccessForPath("path", qt)
	}
	recovered := false
	for range 8 {
		now = now.Add(carrierEvalInterval + time.Second)
		qt := s.nextForPathWithPreference("path", true)
		s.recordSuccessForPath("path", qt)
		if qt == Enums.DNS_RECORD_TYPE_TXT {
			recovered = true
			break
		}
	}
	if !recovered {
		t.Fatal("healthy small-carrier responses permanently starved recovery of bulk polling")
	}
}

func TestCarrierSelector_CursorWrapDoesNotProduceNegativeIndex(t *testing.T) {
	s := newCarrierSelector([]uint16{Enums.DNS_RECORD_TYPE_TXT, Enums.DNS_RECORD_TYPE_CNAME}, nil)
	s.cursor.Store(1 << 31)
	s.bulkCursor.Store(1 << 31)
	for range 4 {
		_ = s.next()
		_ = s.nextWithPreference(true)
	}
}

func BenchmarkCarrierSelectorPathSelection(b *testing.B) {
	for _, bulk := range []bool{false, true} {
		name := "normal"
		if bulk {
			name = "bulk_poll"
		}
		b.Run(name, func(b *testing.B) {
			s := newCarrierSelector([]uint16{Enums.DNS_RECORD_TYPE_TXT, Enums.DNS_RECORD_TYPE_CNAME, Enums.DNS_RECORD_TYPE_NULL, Enums.DNS_RECORD_TYPE_A}, nil)
			s.forPath("resolver")
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					s.nextForPathWithPreference("resolver", bulk)
				}
			})
		})
	}
}
