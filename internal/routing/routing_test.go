package routing

import (
	"reflect"
	"testing"

	"github.com/ehZyiL/connect-hub/internal/workeripc"
)

func domainSnapshot(name string, port int) *workeripc.ResourceSnapshot {
	return &workeripc.ResourceSnapshot{DomainRules: []workeripc.DomainRule{{Domain: name, PortMin: port, PortMax: port, Protocol: "tcp"}}}
}

func TestDomainSemanticsAndRequestValidation(t *testing.T) {
	for _, tc := range []struct {
		pattern, host string
		match         bool
	}{
		{"corp.test", "corp.test", true}, {"corp.test", "x.corp.test", true}, {"corp.test", "evilcorp.test", false},
		{"*.corp.test", "corp.test", false}, {"*.corp.test", "a.b.corp.test", true}, {".corp.test", "a.corp.test", true},
		{"例子.测试", "xn--fsqu00a.xn--0zwm56d", true},
	} {
		if got := DomainSpecificity(tc.pattern, tc.host) > 0; got != tc.match {
			t.Errorf("%+v got %v", tc, got)
		}
	}
	host, port, network, err := ParseRequest(Request{Network: "tcp4", Address: "例子.测试.:443"})
	if err != nil || host != "xn--fsqu00a.xn--0zwm56d" || port != 443 || network != "tcp" {
		t.Fatalf("%s %d %s %v", host, port, network, err)
	}
	for _, address := range []string{"host", "host:0", "host:65536", "bad\nname:443", "user@host:443", "a..test:443"} {
		if _, _, _, err := ParseRequest(Request{Network: "tcp", Address: address}); err == nil {
			t.Errorf("invalid target accepted: %q", address)
		}
	}
}

func TestAttributionBeforeAvailabilityAndAuthorization(t *testing.T) {
	base := []Gateway{
		{ID: "A", Online: true, Strict: true, Current: &workeripc.ResourceSnapshot{IPRules: []workeripc.IPRule{{Min: "10.0.0.0", Max: "10.255.255.255", PortMin: 1, PortMax: 65535, Protocol: "all"}}}},
		{ID: "B", Generation: 3, Online: true, Strict: true, Current: domainSnapshot("b.corp.test", 443)},
	}
	for _, tc := range []struct {
		name, address, network, action string
		mutate                         func([]Gateway)
	}{
		{"exclusive", "b.corp.test:443", "tcp", "vpn", nil},
		{"wrong-port", "b.corp.test:80", "tcp", "blocked", nil},
		{"unsupported-udp", "b.corp.test:443", "udp", "blocked", nil},
		{"offline", "b.corp.test:443", "tcp", "blocked", func(g []Gateway) { g[1].Known = g[1].Current; g[1].Current = nil; g[1].Online = false }},
		{"missing-capability", "b.corp.test:443", "tcp", "blocked", func(g []Gateway) { g[1].Strict = false }},
		{"public", "public.test:443", "tcp", "direct", nil},
		{"same-name-conflict", "b.corp.test:443", "tcp", "blocked", func(g []Gateway) { g[0].Current = domainSnapshot("b.corp.test", 443) }},
		{"more-specific", "b.corp.test:443", "tcp", "vpn", func(g []Gateway) { g[0].Current = domainSnapshot("corp.test", 443) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := append([]Gateway(nil), base...)
			if tc.mutate != nil {
				tc.mutate(g)
			}
			d := Decide(Request{Network: tc.network, Address: tc.address}, g, nil)
			if d.Action != tc.action {
				t.Fatalf("%+v", d)
			}
			if d.Action == "vpn" && (len(d.Candidates) != 1 || d.Candidates[0].ID != "B") {
				t.Fatalf("wrong owner: %+v", d)
			}
		})
	}
}

func TestOverlappingIPsNeedBindingEvenForDifferentPrefixSizes(t *testing.T) {
	s := func(min, max string) *workeripc.ResourceSnapshot {
		return &workeripc.ResourceSnapshot{IPRules: []workeripc.IPRule{{Min: min, Max: max, PortMin: 443, PortMax: 443, Protocol: "tcp"}}}
	}
	gateways := []Gateway{{ID: "A", Online: true, Strict: true, Current: s("10.0.0.0", "10.255.255.255")}, {ID: "B", Online: true, Strict: true, Current: s("10.0.0.8", "10.0.0.8")}}
	r := Request{Network: "tcp", Address: "10.0.0.8:443"}
	if d := Decide(r, gateways, nil); d.Action != "blocked" || len(d.Owners) != 2 {
		t.Fatal(d)
	}
	r.GatewayID = "B"
	if d := Decide(r, gateways, nil); d.Action != "vpn" || d.Candidates[0].ID != "B" {
		t.Fatal(d)
	}
	r.Address = "10.0.0.8:80"
	if d := Decide(r, gateways, nil); d.Action != "blocked" {
		t.Fatal(d)
	}
}

func TestDNSDeclarationsDoNotGrantBareIPOrPorts(t *testing.T) {
	s := &workeripc.ResourceSnapshot{StaticDNS: []workeripc.DNSRecord{{Name: "db.test", Addresses: []string{"10.0.0.8"}}}, InternalDomains: []string{"corp.test"}}
	g := []Gateway{{ID: "B", Online: true, Strict: true, Current: s}}
	for _, host := range []string{"db.test", "app.corp.test"} {
		d := Decide(Request{Network: "tcp", Address: host + ":443"}, g, nil)
		if d.Action != "vpn" || !d.Candidates[0].NeedsResolution {
			t.Fatalf("DNS ownership must require worker authorization: %+v", d)
		}
	}
	if d := Decide(Request{Network: "tcp", Address: "10.0.0.8:443"}, g, nil); d.Action != "blocked" {
		t.Fatal(d)
	}
	s.DomainRules = []workeripc.DomainRule{{Domain: "db.test", PortMin: 443, PortMax: 443, Protocol: "tcp"}}
	if d := Decide(Request{Network: "tcp", Address: "db.test:80"}, g, nil); d.Action != "blocked" {
		t.Fatal(d)
	}
}

func TestExplicitSharedExitsAndRendezvous(t *testing.T) {
	g := []Gateway{{ID: "A", Online: true, Strict: true, Current: domainSnapshot("git.test", 443)}, {ID: "B", Online: true, Strict: true, Current: domainSnapshot("git.test", 443)}}
	groups := []Group{{ID: "git", Pattern: "git.test", Protocol: "tcp", PortMin: 443, PortMax: 443, Gateways: []string{"A", "B"}}}
	r := Request{Network: "tcp", Address: "git.test:443"}
	d := Decide(r, g, groups)
	if d.Action != "vpn" || len(d.Candidates) != 2 {
		t.Fatal(d)
	}
	Rendezvous(d.Candidates, r.Address)
	first := append([]Candidate(nil), d.Candidates...)
	g[0], g[1] = g[1], g[0]
	g = append(g, Gateway{ID: "unrelated", Online: true, Strict: true, Current: domainSnapshot("other.test", 443)})
	d = Decide(r, g, groups)
	Rendezvous(d.Candidates, r.Address)
	if !reflect.DeepEqual(first, d.Candidates) {
		t.Fatalf("unrelated addition/order changed hash: %v %v", first, d.Candidates)
	}
	g[0].Online = false
	if d = Decide(r, g, groups); d.Action != "vpn" || len(d.Candidates) != 1 {
		t.Fatal(d)
	}
}
