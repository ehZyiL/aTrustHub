package wincapture

import (
	"net/netip"
	"testing"
	"time"

	"github.com/qy/easyconnect/internal/workeripc"
)

func TestPublishShorterRefreshKeepsLongerExpiration(t *testing.T) {
	e := &engine{
		aliases:  netip.MustParsePrefix("198.19.0.0/16"),
		adapter:  netip.MustParsePrefix("198.19.0.1/32"),
		mappings: make(map[netip.Addr]aliasEntry),
	}

	addr := netip.MustParseAddr("198.19.0.10")
	orig := netip.MustParseAddr("10.0.0.10")

	// 1. Initial publish with TTL=60
	now := time.Now()
	err := e.publish([]workeripc.DNSAlias{
		{Address: addr.String(), Original: orig.String(), TTL: 60},
	})
	if err != nil {
		t.Fatalf("first publish failed: %v", err)
	}

	entry, ok := e.mappings[addr]
	if !ok {
		t.Fatal("mapping not stored")
	}
	initialExpires := entry.expires
	if initialExpires.Before(now.Add(58 * time.Second)) {
		t.Fatalf("initial expires too short: %v", initialExpires)
	}

	// 2. Refresh with shorter TTL=1 should NOT shorten initialExpires
	time.Sleep(10 * time.Millisecond)
	err = e.publish([]workeripc.DNSAlias{
		{Address: addr.String(), Original: orig.String(), TTL: 1},
	})
	if err != nil {
		t.Fatalf("second publish failed: %v", err)
	}

	updated, ok := e.mappings[addr]
	if !ok {
		t.Fatal("mapping missing after refresh")
	}
	if updated.expires.Before(initialExpires) {
		t.Fatalf("expires was shortened by short TTL refresh: got %v, want >= %v", updated.expires, initialExpires)
	}

	// 3. Refresh with longer TTL should extend it
	extendedTTL := 60
	err = e.publish([]workeripc.DNSAlias{
		{Address: addr.String(), Original: orig.String(), TTL: uint32(extendedTTL)},
	})
	if err != nil {
		t.Fatalf("third publish failed: %v", err)
	}
	extended := e.mappings[addr]
	if extended.expires.Before(initialExpires) {
		t.Fatalf("extended expires was shrunk: %v", extended.expires)
	}
}
