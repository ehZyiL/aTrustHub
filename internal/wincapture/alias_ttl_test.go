//go:build windows

package wincapture

import (
	"net/netip"
	"testing"
	"time"

	"github.com/ehzyil/connect-hub/internal/workeripc"
)

func TestPublishShorterRefreshKeepsLongerExpiration(t *testing.T) {
	s := &captureSession{aliases: netip.MustParsePrefix("198.19.0.0/20"), mappings: make(map[netip.Addr]aliasEntry)}
	e := &engine{
		reserveMapping: func(string, string, time.Time) error { return nil },
		adapter:        netip.MustParsePrefix("198.18.0.0/30"),
		sessions:       map[string]*captureSession{"A": s},
	}

	addr := netip.MustParseAddr("198.19.0.10")
	orig := netip.MustParseAddr("10.0.0.10")

	// 1. Initial publish with TTL=60
	now := time.Now()
	err := e.publish("A", []workeripc.DNSAlias{
		{Address: addr.String(), Original: orig.String(), TTL: 60},
	})
	if err != nil {
		t.Fatalf("first publish failed: %v", err)
	}

	entry, ok := s.mappings[addr]
	if !ok {
		t.Fatal("mapping not stored")
	}
	initialExpires := entry.expires
	if initialExpires.Before(now.Add(58 * time.Second)) {
		t.Fatalf("initial expires too short: %v", initialExpires)
	}

	// 2. Refresh with shorter TTL=1 should NOT shorten initialExpires
	time.Sleep(10 * time.Millisecond)
	err = e.publish("A", []workeripc.DNSAlias{
		{Address: addr.String(), Original: orig.String(), TTL: 1},
	})
	if err != nil {
		t.Fatalf("second publish failed: %v", err)
	}

	updated, ok := s.mappings[addr]
	if !ok {
		t.Fatal("mapping missing after refresh")
	}
	if updated.expires.Before(initialExpires) {
		t.Fatalf("expires was shortened by short TTL refresh: got %v, want >= %v", updated.expires, initialExpires)
	}

	// 3. Refresh with longer TTL should extend it
	extendedTTL := 60
	err = e.publish("A", []workeripc.DNSAlias{
		{Address: addr.String(), Original: orig.String(), TTL: uint32(extendedTTL)},
	})
	if err != nil {
		t.Fatalf("third publish failed: %v", err)
	}
	extended := s.mappings[addr]
	if extended.expires.Before(initialExpires) {
		t.Fatalf("extended expires was shrunk: %v", extended.expires)
	}
}

func TestExpiredPublishedAddressCannotBeRebound(t *testing.T) {
	s := &captureSession{aliases: netip.MustParsePrefix("198.19.0.0/20"), mappings: make(map[netip.Addr]aliasEntry)}
	e := &engine{adapter: netip.MustParsePrefix("198.18.0.0/30"), sessions: map[string]*captureSession{"A": s}}
	e.reserveMapping = func(string, string, time.Time) error { return nil }
	a := workeripc.DNSAlias{Address: "198.19.0.10", Original: "10.0.0.8", TTL: 1}
	if err := e.publish("A", []workeripc.DNSAlias{a}); err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr(a.Address)
	entry := s.mappings[ip]
	entry.expires = time.Now().Add(-time.Second)
	s.mappings[ip] = entry
	a.Original = "10.0.0.9"
	if err := e.publish("A", []workeripc.DNSAlias{a}); err == nil {
		t.Fatal("expired identity rebound")
	}
}

func TestSessionConfigAllowsUpdatedAllocationExclusions(t *testing.T) {
	a := Config{Gateway: "vpn.test", Domains: []string{"corp.test"}, DNSAddress: "127.0.0.1:12345"}
	b := a
	b.ReservedPools = []string{"198.19.0.0/20"}
	if !sameSessionConfig(a, b) {
		t.Fatal("allocation exclusions invalidated established session")
	}
	b.Domains = []string{"other.test"}
	if sameSessionConfig(a, b) {
		t.Fatal("changed DNS scope accepted")
	}
}
