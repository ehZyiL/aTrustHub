package routing

import "testing"

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
