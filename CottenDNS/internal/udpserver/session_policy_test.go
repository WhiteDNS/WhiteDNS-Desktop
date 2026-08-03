// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================

package udpserver

import (
	"testing"

	"cottendns-go/internal/config"
)

// The guarantee that protects every existing CottenDns deployment: a server
// that was never configured with ceilings must produce an empty policy, which
// means no policy block is appended and SESSION_ACCEPT stays byte-for-byte what
// it always was. If this fails, upgrading silently changes the wire.
func TestUnconfiguredServerAdvertisesNoPolicy(t *testing.T) {
	var cfg config.ServerConfig

	if policy := buildClientPolicy(cfg); !policy.IsZero() {
		t.Fatalf("a zero-value server config produced a policy: %+v", policy)
	}
}

// A single configured ceiling must produce a policy carrying that one field and
// nothing else, so operators can enable one limit without implying others.
func TestSingleCeilingProducesMinimalPolicy(t *testing.T) {
	cfg := config.ServerConfig{MaxAllowedClientARQWindowSize: 2000}

	policy := buildClientPolicy(cfg)
	if policy.IsZero() {
		t.Fatal("a configured ceiling produced no policy")
	}
	if policy.MaxARQWindowSize != 2000 {
		t.Fatalf("ARQ window ceiling = %d, want 2000", policy.MaxARQWindowSize)
	}
	if policy.MaxPacketsPerBatch != 0 || policy.MaxDownloadMTU != 0 || policy.MinCompressionMinSize != 0 {
		t.Fatalf("unset ceilings leaked non-zero values: %+v", policy)
	}
}

// The MTU ceilings must bind a client that never reads the advertised policy --
// an older CottenDns client, a MasterDNS client that ignores it, or a modified
// one. The download MTU sizes every response the server builds, so leaving it
// to client goodwill would leave the server's own cost under client control.
func TestSessionMTUCeilingsBindUncooperativeClients(t *testing.T) {
	var record sessionRecord

	// Client asks for far more than the operator allows.
	record.applyMTUFromSessionInit(4000, 4000, 8, 200, 1200)

	if record.UploadMTU != 200 {
		t.Fatalf("upload MTU = %d, want it capped at the configured 200", record.UploadMTU)
	}
	if record.DownloadMTU != 1200 {
		t.Fatalf("download MTU = %d, want it capped at the configured 1200", record.DownloadMTU)
	}
	if record.DownloadMTUBytes != 1200 {
		t.Fatalf("download MTU bytes = %d, want 1200", record.DownloadMTUBytes)
	}
}

// A ceiling states a maximum, not a target: a client asking for less keeps its
// smaller request.
func TestSessionMTUCeilingsDoNotInflateModestRequests(t *testing.T) {
	var record sessionRecord

	record.applyMTUFromSessionInit(120, 600, 8, 200, 1200)

	if record.UploadMTU != 120 {
		t.Fatalf("upload MTU = %d, want the client's own 120", record.UploadMTU)
	}
	if record.DownloadMTU != 600 {
		t.Fatalf("download MTU = %d, want the client's own 600", record.DownloadMTU)
	}
}

// Zero means "no ceiling configured", which must leave the pre-existing
// behaviour exactly as it was: bounded only by the protocol limits.
func TestSessionMTUUnsetCeilingsPreserveLegacyBehaviour(t *testing.T) {
	var withoutCeiling, withCeiling sessionRecord

	withoutCeiling.applyMTUFromSessionInit(4000, 4000, 8, 0, 0)
	withCeiling.applyMTUFromSessionInit(4000, 4000, 8, maxSessionMTU, maxSessionMTU)

	if withoutCeiling.UploadMTU != withCeiling.UploadMTU || withoutCeiling.DownloadMTU != withCeiling.DownloadMTU {
		t.Fatalf("unset ceilings changed behaviour: %d/%d vs %d/%d",
			withoutCeiling.UploadMTU, withoutCeiling.DownloadMTU,
			withCeiling.UploadMTU, withCeiling.DownloadMTU)
	}
}

// An absurdly low ceiling must not produce a session too small to carry a
// packet: the protocol floor still wins.
func TestSessionMTUCeilingNeverFallsBelowProtocolFloor(t *testing.T) {
	var record sessionRecord

	record.applyMTUFromSessionInit(1000, 1000, 8, 1, 1)

	if record.UploadMTU < minSessionMTU || record.DownloadMTU < minSessionMTU {
		t.Fatalf("MTUs %d/%d fell below the protocol floor %d",
			record.UploadMTU, record.DownloadMTU, minSessionMTU)
	}
}
