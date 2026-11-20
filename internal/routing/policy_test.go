package routing

import "testing"

func TestUserPolicyCannotWidenAuthorizationOrRebindMapping(t *testing.T) {
	g := []Gateway{{ID: "A", Online: true, Strict: true, Current: domainSnapshot("corp.test", 443)}, {ID: "B", Online: true, Strict: true, Excluded: true, Current: domainSnapshot("corp.test", 443)}}
	p := Policy{ID: "rule", Pattern: "corp.test", Protocol: "all", PortMin: 1, PortMax: 65535, Action: "gateway", GatewayID: "B"}
	r := Request{Network: "tcp", Address: "corp.test:443"}
	d := Decide(r, g, nil, p)
	if d.Action != "vpn" || d.GatewayID != "B" || len(d.Candidates) != 1 || d.RuleID != "rule" {
		t.Fatal(d)
	}
	r.Address = "corp.test:80"
	if d = Decide(r, g, nil, p); d.Action != "blocked" {
		t.Fatal(d)
	}
	r.Address = "corp.test:443"
	r.GatewayID = "A"
	if d = Decide(r, g, nil, p); d.Action != "blocked" {
		t.Fatal(d)
	}
	r = Request{Network: "tcp", Address: "198.19.0.10:443", OriginalAddress: "corp.test:443", GatewayID: "A", Mapped: true}
	p.Pattern = "corp.test"
	for _, action := range []string{"gateway", "direct", "block"} {
		p.Action = action
		p.GatewayID = ""
		if action == "gateway" {
			p.GatewayID = "B"
		}
		if d = Decide(r, g, nil, p); d.Action != "blocked" {
			t.Fatal(d)
		}
	}
}

func TestPolicyOrderAndExplicitOriginalNetwork(t *testing.T) {
	r := Request{Network: "tcp", Address: "corp.test:443"}
	g := []Gateway{{ID: "B", Known: domainSnapshot("corp.test", 443)}}
	first := Policy{ID: "first", Pattern: "corp.test", Protocol: "tcp", PortMin: 443, PortMax: 443, Action: "direct"}
	second := first
	second.ID = "second"
	second.Action = "block"
	if d := Decide(r, g, nil, first, second); d.Action != "direct" || d.RuleID != "first" {
		t.Fatal(d)
	}
	if d := Decide(r, g, nil, second, first); d.Action != "blocked" || d.RuleID != "second" {
		t.Fatal(d)
	}
}
