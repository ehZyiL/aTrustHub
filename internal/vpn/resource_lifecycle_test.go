package vpn

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/ehzyil/connect-hub/internal/routing"
	"github.com/ehzyil/connect-hub/internal/workeripc"
	zcclient "github.com/mythologyli/zju-connect/client"
)

func routeTestManager(t *testing.T, settings model.Settings, sessions ...Session) *Manager {
	t.Helper()
	var points []model.AccessPoint
	for _, s := range sessions {
		points = append(points, model.AccessPoint{ID: s.(*routeSession).id, Name: s.(*routeSession).id, InPool: true})
	}
	cfg := testConfig(points...)
	cfg.Settings = settings
	m := newTestManager(t, nil, cfg)
	m.mu.Lock()
	for _, s := range sessions {
		id := s.(*routeSession).id
		ep := m.points[id]
		ep.state = StateOnline
		ep.sess = s
		ep.info = cloneSessionInfo(s.Info())
		ep.gen = 1
	}
	m.mu.Unlock()
	return m
}

type routeSession struct {
	*fakeSession
	strictCalls, ordinaryCalls atomic.Int32
	dial                       func(context.Context) (net.Conn, error)
	udp                        bool
}

func (s *routeSession) SupportsStrictUDP() bool { return s.udp }
func (s *routeSession) Done() <-chan struct{}   { return s.done }

func (s *routeSession) Dial(context.Context, string, string) (net.Conn, error) {
	s.ordinaryCalls.Add(1)
	return nil, errors.New("ordinary dial forbidden")
}
func (s *routeSession) DialVPN(ctx context.Context, network, addr string) (net.Conn, error) {
	s.strictCalls.Add(1)
	if s.dial != nil {
		return s.dial(ctx)
	}
	return s.fakeSession.Dial(ctx, network, addr)
}
func routeTestSession(id string) *routeSession {
	s := &routeSession{fakeSession: newFakeSession(id)}
	s.info.Resources = &workeripc.ResourceSnapshot{DomainRules: []workeripc.DomainRule{{Domain: "b.test", PortMin: 443, PortMax: 443, Protocol: "tcp"}}}
	return s
}

func TestOfflineOwnershipSurvivesDisconnect(t *testing.T) {
	s := routeTestSession("B")
	m := routeTestManager(t, model.DefaultSettings(), s)
	m.Disconnect("B")
	if d := m.PreviewRoute(routing.Request{Network: "tcp", Address: "b.test:443"}); d.Action != "blocked" || len(d.Owners) != 1 {
		t.Fatal(d)
	}
	if _, err := m.Dial(context.Background(), "tcp", "b.test:443"); err == nil {
		t.Fatal("offline destination accepted")
	}
	if s.ordinaryCalls.Load() != 0 || s.strictCalls.Load() != 0 {
		t.Fatal("offline dial reached session")
	}
}

func TestLateDialResultCannotUpdateNewGeneration(t *testing.T) {
	s := routeTestSession("B")
	entered, release := make(chan struct{}), make(chan struct{})
	left, right := net.Pipe()
	defer right.Close()
	s.dial = func(context.Context) (net.Conn, error) { close(entered); <-release; return left, nil }
	m := routeTestManager(t, model.DefaultSettings(), s)
	result := make(chan error, 1)
	go func() {
		c, e := m.Dial(context.Background(), "tcp", "b.test:443")
		if c != nil {
			c.Close()
		}
		result <- e
	}()
	<-entered
	m.mu.Lock()
	ep := m.points["B"]
	ep.gen++
	ep.latencyNS.Store(0)
	m.mu.Unlock()
	close(release)
	if err := <-result; !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	if ep.latencyNS.Load() != 0 {
		t.Fatal("old dial contaminated current latency")
	}
	right.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := right.Write([]byte("x")); err == nil {
		t.Fatal("stale connection left open")
	}
}

func TestSharedRetriesHaveSeparateBudgetsAndNoOrdinaryFallback(t *testing.T) {
	a, b := routeTestSession("A"), routeTestSession("B")
	a.dial = func(ctx context.Context) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() }
	settings := model.DefaultSettings()
	settings.Routing = model.RoutingFailover
	settings.DialTimeoutMS = 30
	settings.TotalTimeoutMS = 300
	settings.SharedExits = []routing.Group{{ID: "same", Pattern: "b.test", Protocol: "tcp", PortMin: 443, PortMax: 443, Gateways: []string{"A", "B"}}}
	m := routeTestManager(t, settings, a, b)
	c, err := m.Dial(context.Background(), "tcp", "b.test:443")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	payload, _ := io.ReadAll(c)
	if string(payload) != "B" || a.strictCalls.Load() != 1 || b.strictCalls.Load() != 1 || a.ordinaryCalls.Load() != 0 || b.ordinaryCalls.Load() != 0 {
		t.Fatal("retry escaped allowed strict exits")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.Dial(ctx, "tcp", "b.test:443"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestUnmanagedLoopbackUsesOriginalNetwork(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, e := ln.Accept()
		if e == nil {
			c.Close()
		}
	}()
	s := routeTestSession("B")
	m := routeTestManager(t, model.DefaultSettings(), s)
	c, err := m.Dial(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if s.strictCalls.Load() != 0 || s.ordinaryCalls.Load() != 0 {
		t.Fatal("unmanaged LAN request entered VPN")
	}
}

func TestNetworkSnapshotCopiesAuthorizationAndNotPortalApps(t *testing.T) {
	ips := []zcclient.IPResource{{IPMin: net.ParseIP("10.0.0.1"), IPMax: net.ParseIP("10.0.0.20"), PortMin: 80, PortMax: 443, Protocol: "tcp"}}
	domains := zcclient.DomainResources{"*.test": {{PortMin: 22, PortMax: 22, Protocol: "tcp"}}}
	s := networkResources(ips, domains, map[string][]net.IP{"db.test": {net.ParseIP("10.0.0.2")}}, "10.0.0.53", []string{"test"})
	if len(s.IPRules) != 1 || s.IPRules[0].Max != "10.0.0.20" || len(s.DomainRules) != 1 {
		t.Fatal(s)
	}
	clone := cloneSessionInfo(SessionInfo{Resources: s, Apps: []App{{Name: "portal"}}})
	clone.Resources.StaticDNS[0].Addresses[0] = "203.0.113.1"
	clone.Resources.DomainRules[0].PortMin = 1
	if s.StaticDNS[0].Addresses[0] != "10.0.0.2" || s.DomainRules[0].PortMin != 22 {
		t.Fatal("snapshot mutated through consumer")
	}
}

func TestRevokedResourceRemainsOwnedAcrossReconnect(t *testing.T) {
	s := routeTestSession("B")
	m := routeTestManager(t, model.DefaultSettings(), s)
	m.Disconnect("B")
	m.mu.Lock()
	ep := m.points["B"]
	ep.gen++
	ep.sess = routeTestSession("B")
	ep.info = SessionInfo{Resources: &workeripc.ResourceSnapshot{}}
	ep.resourceVersion = resourceVersion(ep.info.Resources)
	ep.state = StateOnline
	m.mu.Unlock()
	d := m.PreviewRoute(routing.Request{Network: "tcp", Address: "b.test:443"})
	if d.Action != "blocked" || len(d.Owners) != 1 {
		t.Fatal(d)
	}
	if _, err := m.Dial(context.Background(), "tcp", "b.test:443"); err == nil {
		t.Fatal("revoked resource dialed")
	}
}

func TestBoundEntryUsesStrictOutsideAggregatePool(t *testing.T) {
	a, b := routeTestSession("A"), routeTestSession("B")
	a.info.Resources = &workeripc.ResourceSnapshot{DomainRules: []workeripc.DomainRule{{Domain: "a.test", Protocol: "tcp", PortMin: 443, PortMax: 443}}}
	m := routeTestManager(t, model.DefaultSettings(), a, b)
	m.mu.Lock()
	m.points["B"].cfg.InPool = false
	m.mu.Unlock()
	c, err := m.LocalAppConnection("B")
	if err != nil {
		t.Fatal(err)
	}
	stream, err := c.Dial(context.Background(), "tcp", "b.test:443")
	if err != nil {
		t.Fatal(err)
	}
	stream.Close()
	for _, address := range []string{"a.test:443", "b.test:80", "198.19.0.1:443"} {
		if conn, err := c.Dial(context.Background(), "tcp", address); err == nil {
			conn.Close()
			t.Fatalf("accepted %s", address)
		}
	}
	if a.strictCalls.Load() != 0 || b.strictCalls.Load() != 1 || b.ordinaryCalls.Load() != 0 {
		t.Fatal("binding escaped strict session")
	}
}

func TestTotalDialBudgetStopsSharedRetry(t *testing.T) {
	a, b := routeTestSession("A"), routeTestSession("B")
	a.dial = func(ctx context.Context) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() }
	settings := model.DefaultSettings()
	settings.Routing = model.RoutingFailover
	settings.DialTimeoutMS = 100
	settings.TotalTimeoutMS = 20
	settings.SharedExits = []routing.Group{{ID: "same", Pattern: "b.test", Protocol: "tcp", PortMin: 443, PortMax: 443, Gateways: []string{"A", "B"}}}
	m := routeTestManager(t, settings, a, b)
	if _, err := m.Dial(context.Background(), "tcp", "b.test:443"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if b.strictCalls.Load() != 0 {
		t.Fatal("retried after total deadline")
	}
}
