package client

import (
	"sync"
	"testing"
)

func TestResolverRuntimeSnapshotDuringBalancerUpdates(t *testing.T) {
	c := &Client{connections: []Connection{{Key: "resolver", ResolverLabel: "8.8.8.8", IsValid: true, UploadMTUBytes: 100, DownloadMTUBytes: 1200}}, balancer: NewBalancer(BalancingHighestMTU)}
	c.balancer.SetConnections([]*Connection{&c.connections[0]})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			c.balancer.ReclassifyBackups(func(Connection) bool { return i%2 == 0 })
			c.balancer.SetConnectionValidity("resolver", i%3 != 0)
		}
	}()
	go func() {
		defer wg.Done()
		for range 1000 {
			active, _, valid := c.resolverRuntimeSnapshot()
			if len(active) > 1 || len(valid) != 1 || valid[0] != "8.8.8.8" {
				t.Error("inconsistent resolver snapshot")
			}
		}
	}()
	wg.Wait()
}
