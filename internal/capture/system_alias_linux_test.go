package capture

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qy/easyconnect/internal/resolved"
	"github.com/qy/easyconnect/internal/workeripc"
)

func TestSystemSharedAliasRequiresLiveUnusedCapability(t *testing.T) {
	for _, scenario := range []string{"valid", "token", "recovered", "uid", "domains", "prefix", "busy", "duplicate", "guard"} {
		t.Run(scenario, func(t *testing.T) {
			id, token := strings.Repeat("a", 32), strings.Repeat("b", 64)
			a := &sharedAliases{owner: token, route: &aliasRoute{ID: id, UID: 1000, Prefix: "198.19.0.0/20"},
				dns: resolved.Config{Address: "127.0.0.1:12345", Domains: []string{"corp.test"}}}
			s := &Service{uid: 1000, aliases: map[string]*sharedAliases{id: a}, sessions: map[string]*capturedSession{}}
			c := SystemConfig{DNSAddress: "127.0.0.1:12346", Resources: []SystemResource{{ID: "scope", Domains: []string{"corp.test"}, Alias: &AliasRef{ID: id, Token: token}}}}
			switch scenario {
			case "token":
				c.Resources[0].Alias.Token = strings.Repeat("c", 64)
			case "recovered":
				a.owner = ""
			case "uid":
				a.route.UID++
			case "domains":
				c.Resources[0].Domains = []string{"other.test"}
			case "prefix":
				c.Resources[0].RequiredPrefix = "198.19.16.0/20"
			case "busy":
				s.sessions["running"] = &capturedSession{aliasID: id}
			case "duplicate":
				c.Resources = append(c.Resources, c.Resources[0])
			case "guard":
				c.Resources[0].Guard = true
			}
			shared, err := s.systemAliases(c)
			if scenario == "valid" {
				if err != nil || shared["scope"] != a {
					t.Fatal("live lease rejected solely because DNS listeners differ", err)
				}
			} else if err == nil {
				t.Fatal("unauthorized or busy lease transferred")
			}
		})
	}
}

func sharedPublicationRuntime(t *testing.T) (*systemRuntime, *sharedAliases) {
	t.Helper()
	dir := t.TempDir()
	a := &sharedAliases{owner: strings.Repeat("b", 64), dormant: true,
		route:   &aliasRoute{ID: strings.Repeat("a", 32), UID: 1000, Prefix: "198.19.0.0/20"},
		journal: aliasJournal{Version: 1, ID: strings.Repeat("a", 32), UID: 1000, Prefix: "198.19.0.0/20", Entries: map[string]aliasRecord{}}}
	r := &systemRuntime{path: filepath.Join(dir, "system.json"), aliasDir: dir,
		pools:   map[string]*systemPool{"A": {Prefix: netip.MustParsePrefix(a.route.Prefix), Alias: a, Entries: map[netip.Addr]aliasRecord{}}},
		journal: systemJournal{Routes: systemRoutes{routingAllocation: routingAllocation{Mark: 1 << 30, Pref: 1, Table: 10000}, ID: strings.Repeat("c", 32), Source: netip.MustParseAddr("198.18.42.1")}}}
	return r, a
}

func TestSystemSharedPublicationPreservesJournalIdentityAndLifetime(t *testing.T) {
	r, a := sharedPublicationRuntime(t)
	aliases := []workeripc.DNSAlias{{Address: "198.19.0.1", Original: "10.42.0.8", TTL: 60}}
	if err := r.publish("A", aliases); err != nil {
		t.Fatal(err)
	}
	expiry := a.journal.Entries[aliases[0].Address].Expires
	aliases[0].TTL = 1
	if err := r.publish("A", aliases); err != nil || a.journal.Entries[aliases[0].Address].Expires != expiry {
		t.Fatal("short publication reduced the cross-mode lifetime", err)
	}
	saved, err := readAliasJournal(filepath.Join(r.aliasDir, a.route.ID+".json"), 1000)
	if err != nil || saved.Entries[aliases[0].Address].Expires != expiry {
		t.Fatal("return-path journal differs from live mappings", err)
	}
	aliases[0].Original = "10.42.0.9"
	if err := r.publish("A", aliases); err == nil {
		t.Fatal("shared mapping changed original destination")
	}
	if r.journal.Pools[a.route.Prefix] < expiry+int64(aliasRetireGrace) {
		t.Fatal("system crash reservation does not cover the shared lifetime")
	}
}

func TestSystemSharedPublicationRequiresBothDurableJournals(t *testing.T) {
	r, a := sharedPublicationRuntime(t)
	r.aliasDir = filepath.Join(t.TempDir(), "missing")
	aliases := []workeripc.DNSAlias{{Address: "198.19.0.1", Original: "10.42.0.8", TTL: 30}}
	if err := r.publish("A", aliases); err == nil || len(r.pools["A"].Entries) != 0 || len(a.journal.Entries) != 0 {
		t.Fatal("a failed shared journal exposed a live mapping", err)
	}
	journal, err := loadSystemJournal(r.path)
	if err != nil || journal.Pools[a.route.Prefix] == 0 {
		t.Fatal("partial persistence lost the conservative system reservation", err)
	}
}

func TestSystemSharedOwnerLossRevokesOnlyItsScope(t *testing.T) {
	r, a := sharedPublicationRuntime(t)
	now, _ := bootNow()
	addrA, addrB := netip.MustParseAddr("198.19.0.1"), netip.MustParseAddr("198.19.16.1")
	r.pools["A"].Entries[addrA] = aliasRecord{Original: "10.42.0.8", Expires: now + int64(time.Minute)}
	r.pools["B"] = &systemPool{Prefix: netip.MustParsePrefix("198.19.16.0/20"), Entries: map[netip.Addr]aliasRecord{addrB: {Original: "10.43.0.8", Expires: now + int64(time.Minute)}}}
	s := &Service{system: r, aliases: map[string]*sharedAliases{a.route.ID: a}}
	s.releaseOwner(a.owner)
	if s.system != r || !r.pools["A"].Retired || a.owner != "" {
		t.Fatal("lost capability did not revoke just its scope")
	}
	if _, err := r.acquireTarget(addrA); err == nil {
		t.Fatal("ended lease authorized a new flow")
	}
	if release, err := r.acquireTarget(addrB); err != nil {
		t.Fatal("unrelated gateway was interrupted", err)
	} else {
		release()
	}
}

func TestSystemSharedPoolStillRejectsForeignReservationsBeforeMutation(t *testing.T) {
	r, a := sharedPublicationRuntime(t)
	r.routes = map[netip.Prefix]bool{}
	mutations := 0
	r.run = func(_ context.Context, tool, input string, args ...string) ([]byte, error) {
		if tool == "nft" && strings.Join(args, " ") == "-j list ruleset" {
			return []byte(`{"nftables":[]}`), nil
		}
		if tool == "ip" && len(args) > 0 && args[0] == "-j" {
			return []byte(`[]`), nil
		}
		mutations++
		return nil, errors.New("unexpected mutation")
	}
	config := SystemConfig{Resources: []SystemResource{{ID: "A", Gateway: "203.0.113.1", Domains: []string{"corp.test"}, RequiredPrefix: a.route.Prefix}}}
	if err := r.apply(context.Background(), config, []string{a.route.Prefix}, map[string]*sharedAliases{"A": a}); err == nil || mutations != 0 {
		t.Fatal("a capability bypassed another user's reservation", mutations, err)
	}
	if _, err := os.Stat(r.path); !os.IsNotExist(err) {
		t.Fatal("rejected conflict wrote a journal", err)
	}
}
