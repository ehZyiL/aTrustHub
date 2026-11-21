package wincapture

import (
	"net/netip"
	"testing"

	"github.com/ehZyiL/connect-hub/internal/netpolicy"
)

func TestOriginalRoutePreservesTailscale(t *testing.T) {
	routes := []Route{
		{netip.MustParsePrefix("0.0.0.0/0"), 2, 5},
		{netip.MustParsePrefix("10.44.0.0/16"), 7, 30},
		{netip.MustParsePrefix("10.44.0.0/16"), 9, 0},
	}
	r, err := OriginalRoute(netip.MustParseAddr("10.44.1.2"), routes, 9)
	if err != nil || r.Interface != 7 {
		t.Fatalf("route = %+v, %v", r, err)
	}
	routes = append(routes, Route{netip.MustParsePrefix("10.44.0.0/16"), 8, 30})
	if _, err := OriginalRoute(netip.MustParseAddr("10.44.1.2"), routes, 9); err == nil {
		t.Fatal("ambiguous route accepted")
	}
}

func TestResourcePrefixesExact(t *testing.T) {
	prefixes, err := ResourcePrefixes([]netpolicy.Range{{Min: "10.1.0.3", Max: "10.1.1.7"}})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 512; i++ {
		addr := netip.AddrFrom4([4]byte{10, 1, byte(i / 256), byte(i % 256)})
		found := false
		for _, p := range prefixes {
			if p.Contains(addr) {
				found = true
			}
		}
		if found != (i >= 3 && i <= 263) {
			t.Fatalf("wrong coverage at %s", addr)
		}
	}
	for _, r := range []netpolicy.Range{{Min: "0.0.0.0", Max: "255.255.255.255"}, {Min: "2001:db8::1", Max: "2001:db8::2"}} {
		if _, err := ResourcePrefixes([]netpolicy.Range{r}); err == nil {
			t.Fatalf("accepted %v", r)
		}
	}
}

func TestPrefixCollision(t *testing.T) {
	routes := []Route{{netip.MustParsePrefix("198.18.0.0/15"), 7, 0}}
	if _, _, err := choosePrefixes(routes, nil); err == nil {
		t.Fatal("accepted existing fake IP pool")
	}
	routes = []Route{{netip.MustParsePrefix("0.0.0.0/1"), 7, 0}}
	adapter, aliases, err := choosePrefixes(routes, nil)
	if err != nil || adapter.Overlaps(aliases) {
		t.Fatalf("prefix allocation: %v", err)
	}
}

func TestCaptureRejectsOverbroadAndReservedRanges(t *testing.T) {
	for _, r := range []netpolicy.Range{
		{Min: "10.0.0.0", Max: "10.255.255.255"},
		{Min: "127.0.0.1", Max: "127.0.0.1"},
		{Min: "169.254.1.1", Max: "169.254.1.1"},
		{Min: "198.19.0.1", Max: "198.19.0.2"},
		{Min: "224.0.0.1", Max: "224.0.0.1"},
	} {
		if _, err := ResourcePrefixes([]netpolicy.Range{r}); err == nil {
			t.Fatal("unsafe capture accepted", r)
		}
	}
	if _, err := ResourcePrefixes([]netpolicy.Range{{Min: "10.0.0.0", Max: "10.15.255.255"}}); err != nil {
		t.Fatal("bounded capture rejected", err)
	}
	if _, err := ResourcePrefixes([]netpolicy.Range{{Min: "10.0.0.0", Max: "10.15.255.255"}, {Min: "172.16.0.1", Max: "172.16.0.1"}}); err == nil {
		t.Fatal("aggregate limit bypassed")
	}
}
