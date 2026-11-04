//go:build e2e

package e2e

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestE2EHarnessTimeoutBounds(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		requested, remaining time.Duration
		want                 time.Duration
	}{
		{"domain-rotation-budget-preserved", 150 * time.Second, 3 * time.Minute, 150 * time.Second},
		{"short-global-budget", 150 * time.Second, 120 * time.Second, 115 * time.Second},
		{"smaller-operation-budget", 20 * time.Second, 120 * time.Second, 20 * time.Second},
		{"cleanup-reserve-only", time.Minute, cleanupReserve, 0},
		{"global-budget-spent", time.Minute, -time.Second, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := boundedTimeout(tc.requested, tc.remaining); got != tc.want {
				t.Fatalf("wait timeout %s; want %s", got, tc.want)
			}
		})
	}
}

func TestE2EHarnessDNSPortSupportsBothTransports(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			if host == "::1" {
				requireIPv6Loopback(t)
			}
			port := freeUDPPortForHost(t, host)
			network, tcpNetwork := "udp4", "tcp4"
			if host == "::1" {
				network, tcpNetwork = "udp6", "tcp6"
			}
			udp, err := net.ListenPacket(network, net.JoinHostPort(host, fmt.Sprint(port)))
			if err != nil {
				t.Fatal(err)
			}
			defer udp.Close()
			tcp, err := net.Listen(tcpNetwork, net.JoinHostPort(host, fmt.Sprint(port)))
			if err != nil {
				t.Fatal("DNS port was unavailable for TCP", err)
			}
			tcp.Close()
		})
	}
}

func TestE2EHarnessChildCleanup(t *testing.T) {
	if os.Getenv("COTTENDNS_E2E_HELPER_CHILD") == "1" {
		fmt.Println("child ready")
		time.Sleep(time.Minute)
		return
	}
	var cmd *exec.Cmd
	var done <-chan struct{}
	if !t.Run("child", func(t *testing.T) {
		cmd = exec.Command(os.Args[0], "-test.run=^TestE2EHarnessChildCleanup$")
		cmd.Env = append(os.Environ(), "COTTENDNS_E2E_HELPER_CHILD=1")
		cmd.WaitDelay = time.Second
		log := &safeBuf{}
		cmd.Stdout, cmd.Stderr = log, log
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		done = reapChildOnCleanup(t, cmd)
		if err := waitForPattern(log, "child ready", testTimeout(t, 3*time.Second)); err != nil {
			t.Fatalf("helper startup: %v\n%s", err, log.String())
		}
	}) {
		return
	}
	select {
	case <-done:
		if cmd.ProcessState == nil {
			t.Fatal("child cleanup did not wait for process exit")
		}
	default:
		t.Fatal("child remained running after test cleanup")
	}
}
