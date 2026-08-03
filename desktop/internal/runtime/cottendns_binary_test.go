package runtime

import (
	"strings"
	"testing"

	"whitedns-desktop/internal/model"
)

func TestCottenDNSHelperCandidatesAreEngineSpecific(t *testing.T) {
	candidates := helperNameCandidatesForEngine(model.ImportTypeCottenDNS)
	if len(candidates) == 0 {
		t.Fatal("expected CottenDNS helper candidates")
	}
	for _, candidate := range candidates {
		if !strings.Contains(strings.ToLower(candidate), "cottendns") {
			t.Fatalf("CottenDNS candidate must not fall back to another engine: %q", candidate)
		}
	}
	for _, candidate := range helperNameCandidatesForEngine(model.ImportTypeMasterDNS) {
		if strings.Contains(strings.ToLower(candidate), "cottendns") {
			t.Fatalf("MasterDNS candidates must not include CottenDNS: %q", candidate)
		}
	}
}
