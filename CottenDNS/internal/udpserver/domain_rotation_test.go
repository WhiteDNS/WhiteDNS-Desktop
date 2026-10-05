package udpserver

import (
	"strings"
	"testing"
)

func TestAdvertisedDomainsMustBeServed(t *testing.T) {
	got := servedAdvertisedDomains([]string{"a.io", "B.io."}, []string{"b.io", "x.io", "B.IO", " a.io "})
	if strings.Join(got, ",") != "b.io,a.io" {
		t.Fatalf("got %v, want [b.io a.io]", got)
	}
}

func TestEncodeDomainListFitsBudget(t *testing.T) {
	domains := []string{"aaaa.io", "bbbb.io", "cccc.io"} // 7 bytes each
	for budget, wantCount := range map[int]int{6: 0, 7: 1, 14: 1, 15: 2, 23: 3, 100: 3} {
		out := string(encodeDomainList(domains, budget))
		if len(out) > budget {
			t.Fatalf("budget %d: %d bytes", budget, len(out))
		}
		n := 0
		if out != "" {
			n = len(strings.Split(out, "\n"))
		}
		if n != wantCount {
			t.Fatalf("budget %d: %d domains (%q), want %d", budget, n, out, wantCount)
		}
	}
}
