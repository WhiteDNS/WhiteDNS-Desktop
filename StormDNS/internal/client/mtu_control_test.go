package client

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMTUScanControlFilePausesAndResumes(t *testing.T) {
	controlFile := filepath.Join(t.TempDir(), "mtu-control")
	if err := os.WriteFile(controlFile, []byte("pause\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &Client{mtuScanControlFile: controlFile}
	if !c.mtuScanPaused() {
		t.Fatal("expected MTU scan to be paused")
	}
	if err := os.WriteFile(controlFile, []byte("resume\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if c.mtuScanPaused() {
		t.Fatal("expected MTU scan to be resumed")
	}
}

func TestWaitIfMTUScanPausedReturnsAfterResume(t *testing.T) {
	controlFile := filepath.Join(t.TempDir(), "mtu-control")
	if err := os.WriteFile(controlFile, []byte("pause\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &Client{mtuScanControlFile: controlFile}
	done := make(chan bool, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() {
		done <- c.waitIfMTUScanPaused(ctx)
	}()

	select {
	case <-done:
		t.Fatal("wait returned before resume")
	case <-time.After(350 * time.Millisecond):
	}
	if err := os.WriteFile(controlFile, []byte("resume\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("expected wait to report resume")
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for resume")
	}
}

func TestNormalMTUProbeWorkersHonorPauseControl(t *testing.T) {
	controlFile := filepath.Join(t.TempDir(), "mtu-control")
	if err := os.WriteFile(controlFile, []byte("pause\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &Client{
		mtuScanControlFile: controlFile,
		connections: []Connection{{
			Key:           "resolver",
			Domain:        "example.com",
			Resolver:      "127.0.0.1",
			ResolverPort:  53,
			ResolverLabel: "127.0.0.1:53",
		}},
	}
	counters := &mtuScanCounters{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.runAllMTUProbeWorkers(ctx, map[string]int{"example.com": 30}, 1, counters, nil, nil)
	}()

	time.Sleep(350 * time.Millisecond)
	if completed := counters.completed.Load(); completed != 0 {
		cancel()
		<-done
		t.Fatalf("expected paused normal MTU worker not to start probes, completed=%d", completed)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for paused normal MTU worker to stop")
	}
}
