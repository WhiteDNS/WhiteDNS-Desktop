package client

import (
	"os"
	"strings"
	"testing"

	"cottendns-go/internal/config"
	VpnProto "cottendns-go/internal/vpnproto"
)

func newRotationTestClient(t *testing.T, dir string) *Client {
	t.Helper()
	c := New(config.ClientConfig{
		Domains:        []string{"a.io"},
		StandbyDomains: []string{"b.io", "c.io"},
		Resolvers:      []config.ResolverAddress{{IP: "127.0.0.1", Port: 53}},
		ConfigDir:      dir,
		EncryptionKey:  "k",
	}, nil, nil)
	if err := c.BuildConnectionMap(); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestDomainRotationCyclesThroughStandby(t *testing.T) {
	c := newRotationTestClient(t, t.TempDir())
	step := func(wantActive, wantStandby string) {
		t.Helper()
		if c.rotateDomainsAfterFailedScan() {
			t.Fatal("rotated after a single failed scan")
		}
		if !c.rotateDomainsAfterFailedScan() {
			t.Fatal("did not rotate after two failed scans")
		}
		if got := strings.Join(c.cfg.Domains, ","); got != wantActive {
			t.Fatalf("active %q, want %q", got, wantActive)
		}
		if got := strings.Join(c.standbyDomains, ","); got != wantStandby {
			t.Fatalf("standby %q, want %q", got, wantStandby)
		}
		for _, conn := range c.connections {
			if conn.Domain != wantActive {
				t.Fatalf("connection still on %s", conn.Domain)
			}
		}
	}
	step("b.io", "c.io,a.io")
	step("c.io", "a.io,b.io")
	step("a.io", "b.io,c.io")
}

func TestDomainListIsLearnedAndPersisted(t *testing.T) {
	dir := t.TempDir()
	c := newRotationTestClient(t, dir)
	payload := "x.io\nnot a domain\n\nA.IO\nb.io\ny.io"
	if err := c.HandleDomainListRes(VpnProto.Packet{Payload: []byte(payload)}); err != nil {
		t.Fatal(err)
	}
	// Invalid, active (a.io) and already-known (b.io) entries are skipped.
	if got := strings.Join(c.standbyDomains, ","); got != "b.io,c.io,x.io,y.io" {
		t.Fatalf("standby %q", got)
	}
	if _, err := os.Stat(c.learnedDomainsPath()); err != nil {
		t.Fatalf("learned domains not saved: %v", err)
	}
	// A restart with the same key loads them; another key does not.
	if got := strings.Join(newRotationTestClient(t, dir).standbyDomains, ","); got != "b.io,c.io,x.io,y.io" {
		t.Fatalf("after restart: %q", got)
	}
	other := New(config.ClientConfig{Domains: []string{"a.io"}, ConfigDir: dir, EncryptionKey: "other"}, nil, nil)
	if len(other.standbyDomains) != 0 {
		t.Fatalf("learned domains leaked across server keys: %v", other.standbyDomains)
	}
}
