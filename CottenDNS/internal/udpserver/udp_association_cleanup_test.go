package udpserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestUDPIdleSweepRunsWhileKnownDestinationIsActive(t *testing.T) {
	s := &Server{}
	c := newUDPAssociationConn(s)
	defer c.Close()
	old, oldPeer := net.Pipe()
	defer oldPeer.Close()
	active, activePeer := net.Pipe()
	defer activePeer.Close()
	c.mu.Lock()
	c.endpoints["old:443"] = &udpAssociationEndpoint{conn: old, lastUsed: time.Now().Add(-72 * time.Hour), done: make(chan struct{})}
	c.endpoints["active:443"] = &udpAssociationEndpoint{conn: active, lastUsed: time.Now(), done: make(chan struct{})}
	c.aliases["1.1.1.1:443"] = "active:443"
	c.aliases["old-alias:443"] = "old:443"
	s.genericUDPEndpoints.Store(2)
	c.mu.Unlock()
	// Exercise the same periodic sweeper with a short test interval.
	sweepDone := make(chan struct{})
	go func() { defer close(sweepDone); c.cleanupEndpoints(5 * time.Millisecond) }()
	for i := 0; i < 100; i++ {
		if _, err := c.endpointFor("1.1.1.1", 443); err != nil {
			t.Fatal(err)
		}
	}
	limit := time.Now().Add(time.Second)
	for s.genericUDPEndpoints.Load() != 1 && time.Now().Before(limit) {
		time.Sleep(time.Millisecond)
	}
	c.mu.Lock()
	_, retained := c.endpoints["old:443"]
	_, aliasRetained := c.aliases["old-alias:443"]
	c.mu.Unlock()
	if retained || aliasRetained || s.genericUDPEndpoints.Load() != 1 {
		t.Fatal("idle socket or alias survived independent cleanup")
	}
	oldPeer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := oldPeer.Read(make([]byte, 1)); err == nil {
		t.Fatal("idle upstream socket remained open")
	}
	c.Close()
	<-sweepDone
	if s.genericUDPEndpoints.Load() != 0 {
		t.Fatal("endpoint metrics did not return to zero")
	}
}

func TestUDPAliasCapPreservesCanonicalSocket(t *testing.T) {
	var peer net.Conn
	s := &Server{embeddedDialContext: func(context.Context, string, string) (net.Conn, error) {
		local, remote := net.Pipe()
		peer = remote
		return local, nil
	}}
	c := newUDPAssociationConn(s)
	defer func() {
		c.Close()
		if peer != nil {
			peer.Close()
		}
	}()
	var first *udpAssociationEndpoint
	for i := 0; i < 1024; i++ {
		groups := make([]string, 5)
		for j := range groups {
			groups[j] = strings.Repeat("0", 1+((i>>(2*j))&3))
		}
		host := fmt.Sprintf("2606:4700:%s:1111", strings.Join(groups, ":"))
		endpoint, err := c.endpointFor(host, 443)
		if err != nil {
			t.Fatal(err)
		}
		if first == nil {
			first = endpoint
		}
		if endpoint != first {
			t.Fatal("alias eviction replaced the canonical socket")
		}
	}
	c.mu.Lock()
	targets, aliases := len(c.endpoints), len(c.aliases)
	c.mu.Unlock()
	if targets != 1 || aliases > maxUDPAssociationAliases {
		t.Fatalf("targets=%d aliases=%d", targets, aliases)
	}
}

func TestUDPConcurrentDialsRespectTargetCap(t *testing.T) {
	const dials = maxUDPAssociationTargets + 8
	var peersMu sync.Mutex
	var peers []net.Conn
	started := make(chan struct{}, dials)
	release := make(chan struct{})
	s := &Server{embeddedDialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		started <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		local, remote := net.Pipe()
		peersMu.Lock()
		peers = append(peers, remote)
		peersMu.Unlock()
		return local, nil
	}}
	c := newUDPAssociationConn(s)
	defer func() {
		c.Close()
		for _, peer := range peers {
			peer.Close()
		}
	}()
	var wg sync.WaitGroup
	for i := 0; i < dials; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := c.endpointFor(fmt.Sprintf("8.8.8.%d", i+1), 443); err != nil {
				t.Error(err)
			}
		}(i)
	}
	for i := 0; i < dials; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("dial did not start")
		}
	}
	close(release)
	wg.Wait()
	c.mu.Lock()
	count := len(c.endpoints)
	c.mu.Unlock()
	if count > maxUDPAssociationTargets || s.genericUDPEndpoints.Load() != uint64(count) {
		t.Fatalf("target cap/counter mismatch: count=%d metric=%d", count, s.genericUDPEndpoints.Load())
	}
	c.Close()
	if s.genericUDPEndpoints.Load() != 0 {
		t.Fatal("close leaked endpoint accounting")
	}
}

func TestUDPLateDialAfterCloseReleasesSocket(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var peer net.Conn
	s := &Server{embeddedDialContext: func(context.Context, string, string) (net.Conn, error) {
		close(started)
		<-release
		local, remote := net.Pipe()
		peer = remote
		return local, nil
	}}
	c := newUDPAssociationConn(s)
	defer c.Close()
	done := make(chan error, 1)
	go func() { _, err := c.endpointFor("8.8.8.8", 443); done <- err }()
	<-started
	c.Close()
	close(release)
	if err := <-done; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("late dial: %v", err)
	}
	defer peer.Close()
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); err == nil {
		t.Fatal("late dial left socket open")
	}
	if s.genericUDPEndpoints.Load() != 0 {
		t.Fatal("late dial restored a closed association")
	}
}
