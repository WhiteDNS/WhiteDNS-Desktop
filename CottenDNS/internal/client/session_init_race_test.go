package client

import (
	"testing"

	"cottendns-go/internal/config"
)

func TestNextSessionInitRacersReturnsDistinctResolvers(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{}, "a", "b", "c")

	conns, _, verify, err := c.nextSessionInitRacers(3)
	if err != nil {
		t.Fatalf("racers error: %v", err)
	}
	if len(conns) != 3 {
		t.Fatalf("expected 3 racers, got %d", len(conns))
	}
	seen := map[string]bool{}
	for _, cn := range conns {
		if seen[cn.Key] {
			t.Fatalf("duplicate racer %q", cn.Key)
		}
		seen[cn.Key] = true
	}

	// The init token is stable across attempts until a session-init reset, so all
	// racers (this attempt and the next) share one signature — the server dedupes.
	_, _, verify2, err := c.nextSessionInitRacers(3)
	if err != nil {
		t.Fatalf("racers2 error: %v", err)
	}
	if verify != verify2 {
		t.Fatal("verify code must be stable across attempts until session-init reset")
	}
}

func TestNextSessionInitRacersCapsAtValidResolvers(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{}, "only")
	conns, _, _, err := c.nextSessionInitRacers(c.sessionInitRaceCount())
	if err != nil {
		t.Fatalf("racers error: %v", err)
	}
	if len(conns) != 1 {
		t.Fatalf("expected 1 racer with a single valid resolver, got %d", len(conns))
	}
}
