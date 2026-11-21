package dnsmapping

import (
	"fmt"
	"github.com/ehzyil/connect-hub/internal/netpolicy"
	"github.com/ehzyil/connect-hub/internal/workeripc"
	"net/netip"
	"testing"
	"time"
)

func TestRequiredPoolPreservesIdentityWithoutBypassingReservations(t *testing.T) {
	const raw = "198.19.32.0/20"
	prefix := netip.MustParsePrefix(raw)
	if got, err := ChooseRequired(nil, nil, raw); err != nil || got != prefix {
		t.Fatal(got, err)
	}
	for _, occupied := range [][]netip.Prefix{{prefix}, {netip.MustParsePrefix("198.19.0.0/16")}, {netip.MustParsePrefix("198.19.32.1/32")}} {
		if _, err := ChooseRequired(occupied, nil, raw); err == nil {
			t.Fatal("required pool bypassed an existing reservation", occupied)
		}
	}
	if _, err := ChooseRequired(nil, []netpolicy.Range{{Min: "198.19.32.1", Max: "198.19.32.1"}}, raw); err == nil {
		t.Fatal("required pool bypassed an authorized resource")
	}
	r := Registry{}
	id := Identity{Key: "A/1", GatewayID: "A", Generation: 1, Version: "v1"}
	if got, err := r.Prefix(id); got != "" || err != nil || len(r.pools) != 0 {
		t.Fatal("pool lookup allocated a mapping")
	}
	finish, err := r.Begin(id, raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer finish()
	other := id
	other.Generation++
	if got, err := r.Prefix(id); got != raw || err != nil {
		t.Fatal(got, err)
	}
	if _, err := r.Prefix(other); err == nil {
		t.Fatal("pool lookup crossed generation identity")
	}
	r.Retire(id.Key)
	if _, err := r.Prefix(id); err == nil {
		t.Fatal("retired pool was offered to a new capture mode")
	}
}

func TestStageCapacityFailureLeavesWholeBatchUnchanged(t *testing.T) {
	r := Registry{}
	finish, err := r.Begin(Identity{Key: "A", GatewayID: "A"}, "198.19.0.0/20", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer finish()
	// Seed the defensive table limit without depending on allocation policy.
	entries := r.pools["A"].entries
	for i := 0; i < 8191; i++ {
		entries[fmt.Sprint(i)] = entry{}
	}
	aliases := []workeripc.DNSAlias{
		{Address: "198.19.0.1", Original: "10.0.0.1", TTL: 60},
		{Address: "198.19.0.2", Original: "10.0.0.2", TTL: 60},
	}
	if err := r.Stage("A", "db.test", aliases); err == nil {
		t.Fatal("over-capacity publication accepted")
	}
	if len(entries) != 8191 {
		t.Fatal("failed batch partially changed mappings", len(entries))
	}
}

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
