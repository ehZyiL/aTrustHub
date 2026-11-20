package dnsmapping

import (
	"github.com/qy/easyconnect/internal/netpolicy"
	"github.com/qy/easyconnect/internal/workeripc"
	"net/netip"
	"testing"
	"time"
)

func TestAllocatorAvoidsOSResourceAndRetiredPools(t *testing.T) {
	p, err := Choose([]netip.Prefix{netip.MustParsePrefix("198.19.0.0/20")}, []netpolicy.Range{{Min: "198.19.16.1", Max: "198.19.31.255"}})
	if err != nil || p.String() != "198.19.32.0/20" {
		t.Fatalf("%v %v", p, err)
	}
	if _, err = Choose([]netip.Prefix{netip.MustParsePrefix("198.19.0.0/16")}, nil); err == nil {
		t.Fatal("exhausted pool allocated")
	}
}

func TestMappingIdentityPublicationAndRetirement(t *testing.T) {
	now := time.Unix(1000, 0)
	r := Registry{now: func() time.Time { return now }}
	a := Identity{Key: "A/1", GatewayID: "A", Generation: 1, Version: "v1"}
	b := Identity{Key: "B/1", GatewayID: "B", Generation: 1, Version: "v1"}
	finish, err := r.Begin(a, "198.19.0.0/20", nil)
	if err != nil {
		t.Fatal(err)
	}
	aliases := []workeripc.DNSAlias{{Address: "198.19.0.1", Original: "10.0.0.8", TTL: 60}}
	if err = r.Stage(a.Key, "a.test", aliases); err != nil {
		t.Fatal(err)
	}
	if _, _, err = r.Acquire(a.Key, aliases[0].Address); err == nil {
		t.Fatal("used before platform ack")
	}
	if err = r.Confirm(a.Key, aliases); err != nil {
		t.Fatal(err)
	}
	_, release, err := r.Acquire(a.Key, aliases[0].Address)
	if err != nil {
		t.Fatal(err)
	}
	finish()
	if _, err = r.Begin(a, "198.19.16.0/20", nil); err == nil {
		t.Fatal("same generation changed prefix")
	}
	if _, err = r.Begin(b, "198.19.0.0/20", nil); err == nil {
		t.Fatal("another gateway stole pool")
	}
	if err = r.Stage(a.Key, "b.test", aliases); err == nil {
		t.Fatal("synthetic IP rebound to another domain")
	}
	now = now.Add(10 * time.Second)
	aliases[0].TTL = 1
	if err = r.Stage(a.Key, "a.test", aliases); err != nil {
		t.Fatal(err)
	}
	r.Retire(a.Key)
	if pools := r.Reservations(b.Key); len(pools) != 1 || pools[0] != "198.19.0.0/20" {
		t.Fatal("retired pool missing from allocator constraints", pools)
	}
	if _, _, err = r.Acquire(a.Key, aliases[0].Address); err == nil {
		t.Fatal("retired mapping granted new connection")
	}
	now = now.Add(55 * time.Second)
	if _, err = r.Begin(b, "198.19.0.0/20", nil); err == nil {
		t.Fatal("pool recycled during live TCP stream")
	}
	release()
	if pools := r.Reservations(b.Key); len(pools) != 0 {
		t.Fatal("expired drained pool not released", pools)
	}
	finish, err = r.Begin(b, "198.19.0.0/20", nil)
	if err != nil {
		t.Fatal(err)
	}
	finish()
}

func TestRetirementWaitsForInFlightPublication(t *testing.T) {
	r := Registry{}
	a := Identity{Key: "A", GatewayID: "A"}
	b := Identity{Key: "B", GatewayID: "B"}
	finish, err := r.Begin(a, "198.19.0.0/20", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Retire(a.Key)
	if _, err = r.Begin(b, "198.19.0.0/20", nil); err == nil {
		t.Fatal("reused during pending DNS")
	}
	if err = r.Stage(a.Key, "late.test", nil); err == nil {
		t.Fatal("late result accepted")
	}
	finish()
	finish()
	finish, err = r.Begin(b, "198.19.0.0/20", nil)
	if err != nil {
		t.Fatal(err)
	}
	finish()
}

func TestSameRealIPIsScopedAndPublishedTTLNeverShrinks(t *testing.T) {
	now := time.Unix(1000, 0)
	r := Registry{now: func() time.Time { return now }}
	for _, id := range []Identity{{Key: "A", GatewayID: "A"}, {Key: "B", GatewayID: "B"}} {
		prefix, address := "198.19.0.0/20", "198.19.0.1"
		if id.Key == "B" {
			prefix, address = "198.19.16.0/20", "198.19.16.1"
		}
		end, err := r.Begin(id, prefix, nil)
		if err != nil {
			t.Fatal(err)
		}
		end()
		aliases := []workeripc.DNSAlias{{Address: address, Original: "10.0.0.8", TTL: 60}}
		if err = r.Stage(id.Key, id.Key+".test", aliases); err != nil {
			t.Fatal(err)
		}
		if err = r.Confirm(id.Key, aliases); err != nil {
			t.Fatal(err)
		}
		aliases[0].TTL = 1
		r.Stage(id.Key, id.Key+".test", aliases)
	}
	now = now.Add(5 * time.Second)
	for _, tc := range []struct{ key, address string }{{"A", "198.19.0.1"}, {"B", "198.19.16.1"}} {
		target, release, err := r.Acquire(tc.key, tc.address)
		if err != nil || target.GatewayID != tc.key {
			t.Fatal(target, err)
		}
		release()
	}
	if _, _, err := r.Acquire("A", "198.19.16.1"); err == nil {
		t.Fatal("mapping crossed gateway")
	}
}
