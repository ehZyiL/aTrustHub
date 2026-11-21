package capture

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ehzyil/connect-hub/internal/netpolicy"
	"github.com/ehzyil/connect-hub/internal/workeripc"
)

func TestSystemRequiredDNSPoolRejectsBeforeChangingExistingRoutes(t *testing.T) {
	prefix := netip.MustParsePrefix("198.19.0.0/20")
	mutations := 0
	r := &systemRuntime{path: filepath.Join(t.TempDir(), "system.json"), pools: map[string]*systemPool{"A": {Prefix: prefix, Entries: map[netip.Addr]aliasRecord{}}},
		routes: map[netip.Prefix]bool{prefix: true}, journal: systemJournal{Routes: systemRoutes{routingAllocation: routingAllocation{Mark: 1 << 30, Pref: 1, Table: 10000}, ID: strings.Repeat("a", 32), Source: netip.MustParseAddr("198.18.42.1")}},
		run: func(_ context.Context, tool string, _ string, args ...string) ([]byte, error) {
			if tool == "nft" && strings.Join(args, " ") == "-j list ruleset" {
				return []byte(`{"nftables":[]}`), nil
			}
			if tool == "ip" && len(args) > 0 && args[0] == "-j" {
				return []byte(`[]`), nil
			}
			mutations++
			return nil, errors.New("unexpected network mutation")
		}}
	config := SystemConfig{Resources: []SystemResource{{ID: "A", Gateway: "203.0.113.1", Domains: []string{"corp.test"}, RequiredPrefix: "198.19.16.0/20", Networks: []netpolicy.Range{{Min: "192.0.2.40", Max: "192.0.2.40"}}}}}
	if err := r.apply(context.Background(), config, nil); err == nil || !strings.Contains(err.Error(), "worker DNS pool") || mutations != 0 || len(r.routes) != 1 {
		t.Fatalf("incompatible worker prefix changed active capture: mutations=%d routes=%v err=%v", mutations, r.routes, err)
	}
}

func TestSystemRequiredDNSPoolValidation(t *testing.T) {
	c := SystemConfig{Upstream: Upstream{Address: "127.0.0.1:12345", Username: "system", Password: strings.Repeat("a", 64)}, DNSAddress: "127.0.0.1:12346",
		Resources: []SystemResource{{ID: strings.Repeat("a", 32), Gateway: "203.0.113.1", Domains: []string{"corp.test"}, RequiredPrefix: "198.19.32.0/20"}}}
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"198.19.32.1/20", "198.19.0.0/16", "192.0.2.0/24", "2001:db8::/64"} {
		c.Resources[0].RequiredPrefix = raw
		if err := c.validate(); err == nil {
			t.Fatal("accepted invalid worker pool", raw)
		}
	}
}

func TestSystemPublishedPoolsWaitForTTLAndFlows(t *testing.T) {
	now, err := bootNow()
	if err != nil {
		t.Fatal(err)
	}
	prefix := netip.MustParsePrefix("198.19.0.0/20")
	pool := &systemPool{Prefix: prefix, Entries: map[netip.Addr]aliasRecord{}}
	var removed int
	r := &systemRuntime{path: filepath.Join(t.TempDir(), "system.json"), pools: map[string]*systemPool{"A": pool}, routes: map[netip.Prefix]bool{prefix: true},
		journal: systemJournal{Routes: systemRoutes{routingAllocation: routingAllocation{Mark: 1 << 30, Pref: 1, Table: 10000}, ID: strings.Repeat("a", 32), Source: netip.MustParseAddr("198.18.42.1")}},
		run:     func(context.Context, string, string, ...string) ([]byte, error) { removed++; return nil, nil }}
	aliases := []workeripc.DNSAlias{{Address: "198.19.0.1", Original: "10.42.0.8", TTL: 60}}
	if err := r.publish("A", aliases); err != nil {
		t.Fatal(err)
	}
	expiry := r.journal.Pools[prefix.String()]
	aliases[0].TTL = 1
	if err := r.publish("A", aliases); err != nil || r.journal.Pools[prefix.String()] != expiry || expiry < now+int64(60*time.Second) {
		t.Fatal("short TTL shortened a published promise", err)
	}
	journal, err := loadSystemJournal(r.path)
	if err != nil || journal.Pools[prefix.String()] != expiry {
		t.Fatal("publication not durably reserved", err)
	}
	release, err := r.acquireTarget(netip.MustParseAddr("198.19.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	pool.Retired = true
	if _, err := r.acquireTarget(netip.MustParseAddr("198.19.0.1")); err == nil {
		t.Fatal("retired scope authorized a new flow")
	}
	if err := r.publish("A", aliases); err == nil {
		t.Fatal("retired scope accepted a late publication")
	}
	if err := r.prune(context.Background()); err != nil || removed != 0 {
		t.Fatal("live pool removed", err)
	}
	r.journal.Pools[prefix.String()] = now - 1
	if err := r.prune(context.Background()); err != nil || removed != 0 {
		t.Fatal("pool removed with active flow", err)
	}
	release()
	if err := r.prune(context.Background()); err != nil || removed != 1 || len(r.pools) != 0 || len(r.routes) != 0 {
		t.Fatal("drained expired pool remained", err)
	}
}

func TestSystemPublicationFailureLeavesNoUsableMapping(t *testing.T) {
	prefix := netip.MustParsePrefix("198.19.0.0/20")
	pool := &systemPool{Prefix: prefix, Entries: map[netip.Addr]aliasRecord{}}
	r := &systemRuntime{path: filepath.Join(t.TempDir(), "missing", "system.json"), pools: map[string]*systemPool{"A": pool},
		journal: systemJournal{Routes: systemRoutes{routingAllocation: routingAllocation{Mark: 1 << 30, Pref: 1, Table: 10000}, ID: strings.Repeat("a", 32), Source: netip.MustParseAddr("198.18.42.1")}}}
	aliases := []workeripc.DNSAlias{{Address: "198.19.0.1", Original: "10.42.0.8", TTL: 60}}
	if err := r.publish("A", aliases); err == nil || len(pool.Entries) != 0 || len(r.journal.Pools) != 0 {
		t.Fatal("failed journal publication changed active mappings", err)
	}
	aliases[0].Original = "198.19.16.1"
	if err := r.publish("A", aliases); err == nil || len(pool.Entries) != 0 {
		t.Fatal("mapping to another synthetic pool accepted")
	}
}

func TestSystemRuleVerificationDetectsForeignRouteAndEgressChanges(t *testing.T) {
	r := systemRoutes{routingAllocation: routingAllocation{Mark: 1 << 30, Pref: 1, Table: 10000}, ID: strings.Repeat("a", 32), Source: netip.MustParseAddr("198.18.42.1")}
	prefix := netip.MustParsePrefix("192.0.2.40/32")
	base := kernelState{rules: []map[string]any{
		{"priority": json.Number("0"), "table": "local", "src": "all"},
		{"priority": json.Number("1"), "table": json.Number("10000"), "src": "all", "iif": "lo", "fwmark": "0x0", "fwmask": "0x40000000", "protocol": json.Number("242")},
	}, routes: []map[string]any{{"dst": prefix.String(), "dev": r.device(), "prefsrc": r.Source.String(), "table": json.Number("10000"), "protocol": json.Number("242")}}}
	if err := r.verify(base, map[netip.Prefix]bool{prefix: true}); err != nil {
		t.Fatal(err)
	}
	for _, rule := range []map[string]any{
		{"priority": json.Number("20"), "table": json.Number("100"), "fwmark": "0x0", "fwmask": "0x0"},
		{"priority": json.Number("20"), "table": json.Number("100"), "fwmark": "0x40000000", "fwmask": "0x40000000"},
		{"priority": json.Number("0"), "table": json.Number("100")},
	} {
		state := base
		state.rules = append(append([]map[string]any(nil), base.rules...), rule)
		if err := r.verify(state, map[netip.Prefix]bool{prefix: true}); err == nil {
			t.Fatal("foreign egress policy change ignored", rule)
		}
	}
	foreign := map[string]any{"dst": prefix.String(), "table": json.Number("254"), "dev": "foreign"}
	base.routes = append(base.routes, foreign)
	if err := r.checkOverlap(base, []netip.Prefix{prefix}); err == nil {
		t.Fatal("conflicting route was accepted")
	}
}

func TestSystemInstallRollbackRemovesOnlyAddedRoutes(t *testing.T) {
	prefix := netip.MustParsePrefix("192.0.2.40/32")
	var operations []string
	r := &systemRuntime{routes: map[netip.Prefix]bool{}, journal: systemJournal{Routes: systemRoutes{routingAllocation: routingAllocation{Mark: 1 << 30, Pref: 1, Table: 10000}, ID: strings.Repeat("a", 32), Source: netip.MustParseAddr("198.18.42.1")}},
		run: func(_ context.Context, _ string, _ string, args ...string) ([]byte, error) {
			operations = append(operations, strings.Join(args, " "))
			if len(args) > 2 && args[2] == "add" || len(args) > 2 && args[2] == "del" {
				return nil, nil
			}
			return nil, errors.New("snapshot failed after adding route")
		}}
	if err := r.install(context.Background(), map[netip.Prefix]bool{prefix: true}, nil); err == nil || len(operations) != 3 || !strings.Contains(operations[2], "route del "+prefix.String()) {
		t.Fatal("failed route transaction did not roll back", operations, err)
	}
}
