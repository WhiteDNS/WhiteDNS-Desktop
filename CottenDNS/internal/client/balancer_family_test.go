package client

import (
	"net"
	"strings"
	"testing"

	"cottendns-go/internal/config"
)

func TestScopedIPv6ResolverFamily(t *testing.T) {
	const resolver = "fe80::1%eth0"
	if !resolverAddressIsIPv6(resolver) {
		t.Fatalf("scoped resolver %q was not classified as IPv6", resolver)
	}
	if !resolverAddressIsIPv6("[" + resolver + "]") {
		t.Fatalf("bracketed scoped resolver %q was not classified as IPv6", resolver)
	}
	if got := formatResolverEndpoint(resolver, 53); got != "[fe80::1%eth0]:53" {
		t.Fatalf("scoped resolver endpoint = %q", got)
	}

	c := &Client{cfg: config.ClientConfig{
		ResolverIPMode: "ipv6",
		Domains:        []string{"t.example"},
		Resolvers:      []config.ResolverAddress{{IP: resolver, Port: 53}},
	}, resolverAddrCache: make(map[string]*net.UDPAddr)}
	c.balancer = NewBalancer(0)
	if err := c.BuildConnectionMap(); err != nil {
		t.Fatalf("BuildConnectionMap rejected scoped IPv6 resolver: %v", err)
	}
	want4, want6 := c.configuredResolverFamilies()
	if want4 || !want6 {
		t.Fatalf("configured families = v4:%v v6:%v", want4, want6)
	}
}

func TestBalancerAutoPrefersIPv4AndFallsBackToIPv6(t *testing.T) {
	v4 := &Connection{Key: "v4", Resolver: "1.1.1.1", IsValid: true}
	v6 := &Connection{Key: "v6", Resolver: "2606:4700:4700::1111", IsValid: true}
	b := NewBalancer(BalancingRoundRobin)
	b.SetFamilyMode("auto")
	b.SetConnections([]*Connection{v6, v4})

	for i := 0; i < 4; i++ {
		got, ok := b.GetBestConnection()
		if !ok || got.Key != "v4" {
			t.Fatalf("auto mode selected %q, want IPv4", got.Key)
		}
	}

	b.SetConnectionValidity("v4", false)
	got, ok := b.GetBestConnection()
	if !ok || got.Key != "v6" {
		t.Fatalf("auto fallback selected %q, want IPv6", got.Key)
	}
}

func TestBuildConnectionMapFiltersExplicitFamily(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want string
	}{{"ipv4", "1.1.1.1"}, {"ipv6", "2606:4700:4700::1111"}} {
		c := &Client{
			cfg: config.ClientConfig{
				Domains:        []string{"t.example"},
				ResolverIPMode: tc.mode,
				Resolvers: []config.ResolverAddress{
					{IP: "1.1.1.1", Port: 53},
					{IP: "2606:4700:4700::1111", Port: 53},
				},
			},
			balancer:          NewBalancer(BalancingRoundRobin),
			resolverAddrCache: make(map[string]*net.UDPAddr),
		}
		if err := c.BuildConnectionMap(); err != nil {
			t.Fatalf("%s BuildConnectionMap: %v", tc.mode, err)
		}
		if len(c.connections) != 1 || c.connections[0].Resolver != tc.want {
			t.Fatalf("%s connections = %#v, want %s", tc.mode, c.connections, tc.want)
		}
	}
}

func TestBuildConnectionMapRejectsMissingExplicitFamily(t *testing.T) {
	c := &Client{
		cfg: config.ClientConfig{
			Domains:        []string{"t.example"},
			ResolverIPMode: "ipv6",
			Resolvers:      []config.ResolverAddress{{IP: "1.1.1.1", Port: 53}},
		},
		balancer:          NewBalancer(BalancingRoundRobin),
		resolverAddrCache: make(map[string]*net.UDPAddr),
	}
	err := c.BuildConnectionMap()
	if err == nil || !strings.Contains(err.Error(), "no IPV6 resolvers") {
		t.Fatalf("error = %v, want missing IPv6 resolver error", err)
	}
}

func TestBalancerDualUsesBothFamilies(t *testing.T) {
	v4 := &Connection{Key: "v4", Resolver: "8.8.8.8", IsValid: true}
	v6 := &Connection{Key: "v6", Resolver: "2001:4860:4860::8888", IsValid: true}
	b := NewBalancer(BalancingRoundRobin)
	b.SetFamilyMode("dual")
	b.SetConnections([]*Connection{v4, v6})

	got := b.GetUniqueConnections(2)
	if len(got) != 2 {
		t.Fatalf("dual mode returned %d connections, want 2", len(got))
	}
}

func TestBalancerExplicitFamilyModes(t *testing.T) {
	connections := []*Connection{
		{Key: "v4", Resolver: "9.9.9.9", IsValid: true},
		{Key: "v6", Resolver: "2620:fe::fe", IsValid: true},
	}
	for _, tc := range []struct {
		mode string
		want string
	}{{"ipv4", "v4"}, {"ipv6", "v6"}} {
		b := NewBalancer(BalancingRoundRobin)
		b.SetFamilyMode(tc.mode)
		b.SetConnections(connections)
		got, ok := b.GetBestConnection()
		if !ok || got.Key != tc.want {
			t.Fatalf("%s selected %q, want %q", tc.mode, got.Key, tc.want)
		}
	}
}

func TestSessionFailureRotatesAutoFamilyAndReturns(t *testing.T) {
	b := NewBalancer(BalancingRoundRobin)
	b.SetFamilyMode("auto")
	b.SetConnections([]*Connection{
		{Key: "v4", Resolver: "1.1.1.1", IsValid: true},
		{Key: "v6", Resolver: "2606:4700:4700::1111", IsValid: true},
	})
	c := &Client{cfg: config.ClientConfig{ResolverIPMode: "auto"}, balancer: b}
	if !c.rotateResolverFamilyAfterSessionFailure() {
		t.Fatal("first session failure did not activate IPv6")
	}
	got, ok := b.GetBestConnection()
	if !ok || got.Key != "v6" {
		t.Fatalf("fallback selected %q, want v6", got.Key)
	}
	if !c.rotateResolverFamilyAfterSessionFailure() {
		t.Fatal("second session failure did not return to IPv4")
	}
	got, ok = b.GetBestConnection()
	if !ok || got.Key != "v4" {
		t.Fatalf("return selected %q, want v4", got.Key)
	}
}

func TestAutoFallsBackToIPv6MTUReserve(t *testing.T) {
	v4 := &Connection{Key: "v4", Resolver: "1.1.1.1", IsValid: true}
	v6 := &Connection{Key: "v6", Resolver: "2606:4700:4700::1111", IsValid: true, Backup: true}
	b := NewBalancer(BalancingRoundRobin)
	b.SetFamilyMode("auto")
	b.SetConnections([]*Connection{v4, v6})
	b.SetConnectionValidity("v4", false)
	got, ok := b.GetBestConnection()
	if !ok || got.Key != "v6" {
		t.Fatalf("auto reserve fallback selected %q, want v6", got.Key)
	}
}

func TestOperatingPointPoolFollowsAutoFamily(t *testing.T) {
	c := &Client{cfg: config.ClientConfig{ResolverIPMode: "auto"}}
	conns := []Connection{
		{Key: "v4", Resolver: "1.1.1.1", IsValid: true, DownloadMTUBytes: 1000},
		{Key: "v6", Resolver: "2606:4700:4700::1111", IsValid: true, DownloadMTUBytes: 4000},
	}
	got := c.resolverConnectionsForOperatingPoint(conns)
	if len(got) != 1 || got[0].Key != "v4" {
		t.Fatalf("auto operating pool = %#v, want IPv4 only", got)
	}
	c.ipv6FallbackActive.Store(true)
	got = c.resolverConnectionsForOperatingPoint(conns)
	if len(got) != 1 || got[0].Key != "v6" {
		t.Fatalf("fallback operating pool = %#v, want IPv6 only", got)
	}
}
