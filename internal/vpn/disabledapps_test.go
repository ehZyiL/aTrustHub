package vpn

import (
	"testing"

	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/ehzyil/connect-hub/internal/routing"
	"github.com/ehzyil/connect-hub/internal/workeripc"
)

func resourcesWithApps() *workeripc.ResourceSnapshot {
	return &workeripc.ResourceSnapshot{
		IPRules: []workeripc.IPRule{
			{Min: "10.0.0.10", Max: "10.0.0.10", PortMin: 443, PortMax: 443, Protocol: "tcp", AppID: "keep"},
			{Min: "10.0.0.11", Max: "10.0.0.11", PortMin: 443, PortMax: 443, Protocol: "tcp", AppID: "off"},
			{Min: "10.0.0.12", Max: "10.0.0.12", PortMin: 443, PortMax: 443, Protocol: "tcp"},
		},
		DomainRules: []workeripc.DomainRule{
			{Domain: "keep.corp", PortMin: 443, PortMax: 443, Protocol: "tcp", AppID: "keep"},
			{Domain: "off.corp", PortMin: 443, PortMax: 443, Protocol: "tcp", AppID: "off"},
		},
		InternalDomains: []string{"corp"},
	}
}

func TestFilterDisabledAppsSnapshot(t *testing.T) {
	snapshot := resourcesWithApps()
	if got := filterDisabledAppsSnapshot(nil, []string{"off"}); got != nil {
		t.Fatal("nil snapshot must stay nil")
	}
	if got := filterDisabledAppsSnapshot(snapshot, nil); got != snapshot {
		t.Fatal("without disabled apps the snapshot must be returned unchanged")
	}
	got := filterDisabledAppsSnapshot(snapshot, []string{"off", ""})
	if len(got.IPRules) != 2 || got.IPRules[0].AppID != "keep" || got.IPRules[1].AppID != "" {
		t.Fatalf("ip rules = %+v", got.IPRules)
	}
	if len(got.DomainRules) != 1 || got.DomainRules[0].Domain != "keep.corp" {
		t.Fatalf("domain rules = %+v", got.DomainRules)
	}
	// A rule with no attribution is kept: dropping it would take access away
	// from applications the user never switched off.
	if len(got.InternalDomains) != 1 {
		t.Fatal("internal domains must survive the filter")
	}
	if len(snapshot.IPRules) != 3 || len(snapshot.DomainRules) != 2 {
		t.Fatal("the reported snapshot was mutated")
	}
}

// N6: switching an application off takes effect for new decisions immediately,
// without logging in again, and the mapping identity stays stable.
func TestDisabledAppsApplyWithoutReconnect(t *testing.T) {
	session := newFakeSession("A")
	session.info.Resources = resourcesWithApps()
	point := model.AccessPoint{
		ID: "p1", Name: "A", Server: "vpn.test", Port: 443,
		InPool: true, AuthMode: string(model.AuthModePassword), Protocol: model.ProtocolATrust,
	}
	m := NewManager(nil, nil, nil, nil)
	defer m.Close()
	ep := &endpoint{cfg: point, state: StateOnline, sess: session, gen: 1}
	m.mu.Lock()
	m.points[point.ID] = ep
	m.order = append(m.order, point.ID)
	m.settings = model.DefaultSettings()
	m.mu.Unlock()
	m.mu.Lock()
	ep.rawResources = session.info.Resources
	ep.publishResourcesLocked()
	m.mu.Unlock()

	route := func(addr string) routing.Decision {
		return m.PreviewRoute(routing.Request{Network: "tcp", Address: addr})
	}
	if got := route("10.0.0.11:443"); got.Action != "vpn" {
		t.Fatalf("before the switch: %s", got.Action)
	}
	before, err := m.LocalAppConnection(point.ID)
	if err != nil {
		t.Fatal(err)
	}

	// What the UI does: save the point with one application switched off.
	off := point
	off.DisabledApps = []string{"off"}
	m.Apply(model.Config{Settings: model.DefaultSettings(), Points: []model.AccessPoint{off}})

	if got := route("10.0.0.11:443"); got.Action == "vpn" {
		t.Fatalf("a disabled application is still routed through the tunnel: %+v", got)
	}
	if got := route("10.0.0.10:443"); got.Action != "vpn" {
		t.Fatalf("an enabled application lost its route: %+v", got)
	}
	// The routing generation must not move with the switch: in-flight dials carry
	// the version they were decided with, and a toggle is not a new session.
	gateways, _, _ := m.routeSnapshot("")
	if len(gateways) != 1 {
		t.Fatalf("gateways = %+v", gateways)
	}
	if gateways[0].Version != resourceVersion(session.info.Resources) {
		t.Fatalf("routing version follows the filtered snapshot (%s)", gateways[0].Version)
	}
	after, err := m.LocalAppConnection(point.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Identity.Version != before.Identity.Version {
		t.Fatal("the mapping identity changed with the switch; the DNS pool would be rebound")
	}
	if len(after.Resources.IPRules) != 2 {
		t.Fatalf("capture config still carries the disabled rules: %+v", after.Resources.IPRules)
	}
	if len(before.Resources.IPRules) != 3 {
		t.Fatal("the earlier snapshot was mutated in place")
	}
}

// The same switch must take effect before the first login too: a point saved with
// disabled applications filters what the fresh session reports.
func TestDisabledAppsFilterAtPublish(t *testing.T) {
	ep := &endpoint{
		cfg:          model.AccessPoint{ID: "p1", DisabledApps: []string{"off"}},
		rawResources: resourcesWithApps(),
	}
	ep.publishResourcesLocked()
	if len(ep.info.Resources.IPRules) != 2 {
		t.Fatalf("rules = %+v", ep.info.Resources.IPRules)
	}
	if ep.resourceVersion != resourceVersion(ep.rawResources) {
		t.Fatal("resource version must follow the reported snapshot")
	}
}
