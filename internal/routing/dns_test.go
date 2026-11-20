package routing

import "testing"

func TestDNSExplicitEquivalentGroupUsesOnlyOnlineCurrentOwners(t *testing.T) {
	g := []Gateway{{ID: "A", Online: true, Current: domainSnapshot("corp.test", 443)}, {ID: "B", Online: true, Current: domainSnapshot("corp.test", 443)}}
	group := Group{ID: "same-business", Pattern: "corp.test", Protocol: "tcp", PortMin: 443, PortMax: 443, Gateways: []string{"B", "A"}, DNSFailover: true}
	check := func(want string, bound string, bindings []DNSBinding) {
		t.Helper()
		d := DecideDNS("corp.test.", bound, g, bindings, group)
		if want == "" {
			if d.Action != "blocked" {
				t.Fatalf("ambiguous/unavailable DNS selected a gateway: %+v", d)
			}
		} else if d.Action != "vpn" || len(d.Candidates) != 1 || d.Candidates[0].ID != want {
			t.Fatalf("DNS selection = %+v, want %s", d, want)
		}
	}
	check("B", "", nil)
	g[1].Known, g[1].Current, g[1].Online = g[1].Current, nil, false
	check("A", "", nil)
	check("", "B", nil)
	check("", "", []DNSBinding{{ID: "pinned", Pattern: "corp.test", GatewayID: "B"}})
	g[1].Current, g[1].Online = g[1].Known, true
	check("B", "", nil)
	group.DNSFailover = false
	check("", "", nil)
	group.DNSFailover = true
	g[1].Known, g[1].Current, g[1].Online = g[1].Current, nil, false
	g[0].Known, g[0].Current, g[0].Online = g[0].Current, nil, false
	check("", "", nil)
	g[0].Known, g[0].Current, g[0].Online = nil, domainSnapshot("test", 443), true
	check("", "", nil) // A broader current claim cannot replace B's exact offline ownership.
	g[0].Current, g[1].Current, g[1].Online = domainSnapshot("corp.test", 443), g[1].Known, true
	g = append(g, Gateway{ID: "C", Online: true, Current: domainSnapshot("corp.test", 443)})
	check("", "", nil)
}

func TestDNSOwnershipHasNoBusinessPortAndRetainsOfflineClaims(t *testing.T) {
	g := []Gateway{{ID: "A", Online: true, Current: domainSnapshot("corp.test", 443)}, {ID: "B", Online: true, Current: domainSnapshot("corp.test", 3306)}}
	if d := DecideDNS("corp.test.", "", g, nil); d.Action != "blocked" || len(d.Owners) != 2 {
		t.Fatal(d)
	}
	b := []DNSBinding{{ID: "dns", Pattern: "corp.test", GatewayID: "B"}}
	if d := DecideDNS("corp.test.", "", g, b); d.Action != "vpn" || d.Candidates[0].ID != "B" {
		t.Fatal(d)
	}
	g[1].Known = g[1].Current
	g[1].Current = nil
	g[1].Online = false
	if d := DecideDNS("corp.test", "", g, b); d.Action != "blocked" || len(d.Owners) != 1 {
		t.Fatal(d)
	}
	if d := DecideDNS("public.test", "", g, b); d.Action != "blocked" || len(d.Owners) != 0 {
		t.Fatal(d)
	}
}
