package vpn

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/ehzyil/connect-hub/internal/relay"
	"github.com/ehzyil/connect-hub/internal/routing"
	"github.com/ehzyil/connect-hub/internal/workeripc"
)

func shareTestResources() *workeripc.ResourceSnapshot {
	return &workeripc.ResourceSnapshot{
		Tunnel:          "ipv4-l3",
		DNSServer:       "10.0.0.53",
		InternalDomains: []string{"corp.test"},
		IPRules: []workeripc.IPRule{
			{Min: "10.1.0.0", Max: "10.1.255.255", PortMin: 443, PortMax: 443, Protocol: "tcp"},
			{Min: "10.2.0.0", Max: "10.2.0.255", PortMin: 53, PortMax: 53, Protocol: "udp"},
			{Min: "10.3.0.0", Max: "10.3.0.255", PortMin: 22, PortMax: 22, Protocol: "all"},
		},
		DomainRules: []workeripc.DomainRule{
			{Domain: "corp.test", PortMin: 443, PortMax: 443, Protocol: "tcp"},
		},
		StaticDNS: []workeripc.DNSRecord{{Name: "git.corp.test", Addresses: []string{"10.1.0.9"}}},
	}
}

func startShareTestPoint(t *testing.T, cfg model.Config) (*Manager, *fakeConnector) {
	t.Helper()
	return startShareTestPointWithSession(t, cfg, newFakeSession(cfg.Points[0].ID))
}

// startShareTestPointWithSession connects a session whose Info already carries
// the resources. Mutating Info after Connect would race with the manager's own
// read of it, which is a test artifact, not a production path.
func startShareTestPointWithSession(t *testing.T, cfg model.Config, sess *fakeSession) (*Manager, *fakeConnector) {
	t.Helper()
	conn := &fakeConnector{}
	m := newTestManager(t, func(context.Context, model.AccessPoint, Credentials) (Session, error) {
		return sess, nil
	}, cfg)
	_ = conn
	m.Connect(cfg.Points[0].ID)
	waitFor(t, "point online", func() bool {
		online, _, _ := m.Counts()
		return online == 1
	})
	return m, conn
}

func sharePointConfig() model.Config {
	return testConfig(model.AccessPoint{
		ID:       "p1",
		Name:     "公司 VPN",
		Protocol: model.ProtocolATrust,
		Server:   "vpn.example.com",
		Port:     443,
		Username: "u",
		InPool:   true,
	})
}

func TestRelayShareSourcePublishesTCPOnly(t *testing.T) {
	cfg := sharePointConfig()
	sess := newFakeSession("p1")
	sess.info.Resources = shareTestResources()
	m, _ := startShareTestPointWithSession(t, cfg, sess)

	src, err := m.AcquireRelayShareSource("p1")
	if err != nil {
		t.Fatalf("AcquireRelayShareSource: %v", err)
	}
	t.Cleanup(func() { _ = src.Close() })
	snap, err := src.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if !snap.Capabilities.StrictTCP {
		t.Fatal("strict TCP must be declared")
	}
	if snap.Capabilities.InternalDNS {
		t.Fatal("a session without DNSExchanger must not declare internal DNS")
	}
	for _, r := range snap.Resources.IPRules {
		if r.Protocol != "tcp" {
			t.Fatalf("published rule is not TCP: %+v", r)
		}
	}
	if len(snap.Resources.IPRules) != 2 {
		t.Fatalf("want the TCP and narrowed 'all' rules, got %+v", snap.Resources.IPRules)
	}
	if snap.Revision == "" {
		t.Fatal("revision must not be empty")
	}
	// Revision must be deterministic across equal snapshots.
	again := relayResources(shareTestResources()).PublishTCP().Revision(snap.Capabilities)
	if again != snap.Revision {
		t.Fatalf("revision is not deterministic: %s != %s", again, snap.Revision)
	}
}

func TestRelayShareSourceRefusesUnknownTargets(t *testing.T) {
	sess := newFakeSession("p1")
	sess.info.Resources = shareTestResources()
	m, _ := startShareTestPointWithSession(t, sharePointConfig(), sess)

	src, err := m.AcquireRelayShareSource("p1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = src.Close() })
	snap, _ := src.Snapshot(context.Background())

	cases := []struct {
		target string
		code   relay.Code
	}{
		{"10.1.1.1:443", ""},                        // authorized
		{"git.corp.test:443", ""},                   // authorized domain
		{"10.3.0.5:22", ""},                         // "all" narrowed to TCP
		{"8.8.8.8:443", relay.CodeResourceDenied},   // plain public: never through A
		{"1.1.1.1:53", relay.CodeResourceDenied},    // unknown
		{"10.1.1.1:8443", relay.CodeResourceDenied}, // port not authorized
		{"10.2.0.5:53", relay.CodeResourceDenied},   // UDP-only rule grants no TCP
		// An internal-domain claim is attribution only; the strict session
		// validates the resolved answer and port.
		{"other.corp.test:443", ""},
	}
	for _, tc := range cases {
		connOut, err := src.DialVPN(context.Background(), snap.Revision, tc.target)
		if tc.code == "" {
			if err != nil {
				t.Fatalf("%s: expected success, got %v", tc.target, err)
			}
			_, _ = io.Copy(io.Discard, connOut)
			_ = connOut.Close()
			continue
		}
		if err == nil {
			_ = connOut.Close()
			t.Fatalf("%s: expected refusal", tc.target)
		}
		var re *relay.Error
		if !errors.As(err, &re) || re.Code != tc.code {
			t.Fatalf("%s: want code %s, got %v", tc.target, tc.code, err)
		}
	}
}

func TestRelayShareSourceRefusesDirectPolicy(t *testing.T) {
	cfg := sharePointConfig()
	// A local policy that sends a managed range to the original network must
	// not become a public exit for the share.
	cfg.Settings.RoutePolicies = []routing.Policy{{
		ID: "p-direct", Pattern: "10.1.0.0/16", Protocol: "tcp", PortMin: 1, PortMax: 65535, Action: "direct",
	}}
	sess := newFakeSession("p1")
	sess.info.Resources = shareTestResources()
	m, _ := startShareTestPointWithSession(t, cfg, sess)

	src, err := m.AcquireRelayShareSource("p1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = src.Close() })
	snap, _ := src.Snapshot(context.Background())
	connOut, err := src.DialVPN(context.Background(), snap.Revision, "10.1.1.1:443")
	if err == nil {
		_ = connOut.Close()
		t.Fatal("direct policy must refuse, never dial the original network")
	}
	var re *relay.Error
	if !errors.As(err, &re) || re.Code != relay.CodeResourceDenied {
		t.Fatalf("want resource_denied, got %v", err)
	}
}

func TestRelayShareSourceRefusesStaleRevision(t *testing.T) {
	sess := newFakeSession("p1")
	sess.info.Resources = shareTestResources()
	m, _ := startShareTestPointWithSession(t, sharePointConfig(), sess)
	src, err := m.AcquireRelayShareSource("p1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = src.Close() })
	connOut, err := src.DialVPN(context.Background(), "deadbeef", "10.1.1.1:443")
	if err == nil {
		_ = connOut.Close()
		t.Fatal("stale revision must be refused")
	}
	var re *relay.Error
	if !errors.As(err, &re) || re.Code != relay.CodeStaleResources {
		t.Fatalf("want stale_resources, got %v", err)
	}
}

// watchSession adds the watcher surface the real sessions expose, so the
// reconnect/teardown path is exercised instead of a session that silently
// never ends.
type watchSession struct {
	*fakeSession
	done chan struct{}
	once sync.Once
}

func (w *watchSession) Done() <-chan struct{} { return w.done }
func (w *watchSession) Err() error            { return nil }

func (w *watchSession) Close() error {
	w.once.Do(func() { close(w.done) })
	return w.fakeSession.Close()
}

func TestRelayShareSourceEndsOnSessionLoss(t *testing.T) {
	ws := &watchSession{fakeSession: newFakeSession("p1"), done: make(chan struct{})}
	ws.info.Resources = shareTestResources()
	m := newTestManager(t, func(context.Context, model.AccessPoint, Credentials) (Session, error) {
		return ws, nil
	}, sharePointConfig())
	t.Cleanup(func() { _ = ws.Close() })
	m.Connect("p1")
	waitFor(t, "point online", func() bool { online, _, _ := m.Counts(); return online == 1 })

	src, err := m.AcquireRelayShareSource("p1")
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-src.Done():
		t.Fatal("source ended while the session was still online")
	default:
	}
	// Simulate the VPN dropping.
	_ = ws.Close()
	select {
	case <-src.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("source did not end after the session dropped")
	}
}

func TestRelayShareSourceRejectsRelayAndTunServed(t *testing.T) {
	relayPoint := model.AccessPoint{
		ID: "r1", Name: "同事分享", Protocol: model.ProtocolLANRelay,
		Server: "192.168.1.50", Port: 23456, InPool: true,
		Relay: &model.RelayPointOptions{Version: 1},
	}
	m, _ := startShareTestPoint(t, testConfig(relayPoint))
	if _, err := m.AcquireRelayShareSource("r1"); err == nil {
		t.Fatal("a relay node must not be shareable")
	}
}

func TestStrictCapabilityRejectsPlainSession(t *testing.T) {
	if strictCapable(nil) {
		t.Fatal("nil session is not strict capable")
	}
	if strictCapable(&processSession{}) {
		t.Fatal("an unnegotiated process session is not strict capable")
	}
	if !strictCapable(newFakeSession("x")) {
		t.Fatal("a StrictSession must be accepted")
	}
}

// TestRelayPointIsExcludedFromAppCapture keeps the transparent capture path from
// silently binding a session that has no ipv4-l3 identity.
func TestRelayPointIsExcludedFromAppCapture(t *testing.T) {
	point := model.AccessPoint{
		ID: "r1", Name: "同事分享", Protocol: model.ProtocolLANRelay,
		Server: "192.168.1.50", Port: 23456, InPool: true,
		Relay: &model.RelayPointOptions{Version: 1, ShareID: base64Raw16(), CertificateSHA256: strings.Repeat("ab", 32)},
	}
	sess := newFakeSession("r1")
	sess.info.Resources = shareTestResources()
	m, _ := startShareTestPointWithSession(t, testConfig(point), sess)
	if _, err := m.LocalAppConnection("r1"); !errors.Is(err, ErrRelayNotCapturable) {
		t.Fatalf("relay node entered the capture path: %v", err)
	}
}

func base64Raw16() string {
	b := make([]byte, 16)
	for i := range b {
		b[i] = byte('a' + i%26)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// TestNeedsRestartRelayIdentity pins which relay changes reconnect a node: the
// share identity yes, the history marker no.
func TestNeedsRestartRelayIdentity(t *testing.T) {
	base := model.AccessPoint{
		ID: "r1", Protocol: model.ProtocolLANRelay, Server: "192.168.1.50", Port: 23456,
		InPool: true,
		Relay:  &model.RelayPointOptions{Version: 1, ShareID: base64Raw16(), CertificateSHA256: strings.Repeat("ab", 32)},
	}
	clone := func() model.AccessPoint {
		out := base
		relay := *base.Relay
		out.Relay = &relay
		return out
	}
	if needsRestart(base, clone()) {
		t.Fatal("an identical relay point requested a restart")
	}
	marked := clone()
	marked.Relay.HistoryInitialized = true
	if needsRestart(base, marked) {
		t.Fatal("the history marker must not trigger a reconnect")
	}
	newShare := clone()
	newShare.Relay.ShareID = base64Raw16() + "A"
	if !needsRestart(base, newShare) {
		t.Fatal("a changed share ID must reconnect")
	}
	newPin := clone()
	newPin.Relay.CertificateSHA256 = strings.Repeat("cd", 32)
	if !needsRestart(base, newPin) {
		t.Fatal("a changed certificate pin must reconnect")
	}
	newVersion := clone()
	newVersion.Relay.Version = 2
	if !needsRestart(base, newVersion) {
		t.Fatal("a changed protocol version must reconnect")
	}
	if !needsRestart(base, model.AccessPoint{ID: "r1", Protocol: model.ProtocolATrust}) {
		t.Fatal("dropping the relay metadata must reconnect")
	}
}
