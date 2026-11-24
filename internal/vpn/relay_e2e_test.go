package vpn

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/ehzyil/connect-hub/internal/relay"
	"github.com/ehzyil/connect-hub/internal/routing"
	"github.com/ehzyil/connect-hub/internal/workeripc"
)

// echoStrictSession is A's VPN session: it authorizes one corporate range and
// echoes bytes back, so a tunnel that reaches it can be proven end to end.
type echoStrictSession struct {
	*fakeSession
	mu    sync.Mutex
	seen  []string
	allow string
}

func (e *echoStrictSession) DialVPN(ctx context.Context, network, addr string) (net.Conn, error) {
	e.mu.Lock()
	e.seen = append(e.seen, addr)
	e.mu.Unlock()
	if !strings.HasPrefix(addr, e.allow) {
		return nil, errors.New("目标不在 VPN 授权范围内")
	}
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		buf := make([]byte, 4096)
		for {
			n, err := server.Read(buf)
			if n > 0 {
				if _, werr := server.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	return client, nil
}

func (e *echoStrictSession) dials() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.seen...)
}

func corpResources() *workeripc.ResourceSnapshot {
	return &workeripc.ResourceSnapshot{
		Tunnel:          "ipv4-l3",
		InternalDomains: []string{"corp.test"},
		IPRules: []workeripc.IPRule{
			{Min: "10.5.0.0", Max: "10.5.255.255", PortMin: 443, PortMax: 443, Protocol: "tcp"},
		},
		DomainRules: []workeripc.DomainRule{{Domain: "git.corp.test", PortMin: 443, PortMax: 443, Protocol: "tcp"}},
	}
}

func randomB64(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// TestHeadlessLanRelayEndToEnd is the no-UI acceptance path: B's authorized
// resource reaches A's VPN, B's ordinary public traffic stays on B's own
// network, A refuses an unknown target, and revoking the share closes a live
// tunnel while keeping the known attribution from falling back to direct.
func TestHeadlessLanRelayEndToEnd(t *testing.T) {
	// ---- A: sharing host -------------------------------------------------
	aSess := &echoStrictSession{fakeSession: newFakeSession("a1"), allow: "10.5."}
	aSess.info.Resources = corpResources()
	aCfg := testConfig(model.AccessPoint{
		ID: "a1", Name: "公司 VPN", Protocol: model.ProtocolATrust,
		Server: "vpn.example.com", Port: 443, Username: "u", InPool: true,
	})
	aMgr := newTestManager(t, func(context.Context, model.AccessPoint, Credentials) (Session, error) {
		return aSess, nil
	}, aCfg)
	aMgr.Connect("a1")
	waitFor(t, "A online", func() bool { online, _, _ := aMgr.Counts(); return online == 1 })

	source, err := aMgr.AcquireRelayShareSource("a1")
	if err != nil {
		t.Fatalf("AcquireRelayShareSource: %v", err)
	}
	identity, err := relay.GenerateIdentity("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	shareID := randomB64(16)
	shareToken := randomB64(32)
	server, err := relay.StartServer(relay.ServerOptions{
		Identity: identity, Source: source, Token: shareToken,
		ShareID: shareID, ServerInstanceID: "a-instance", Port: 0,
		Lease: 15 * time.Second,
	})
	if err != nil {
		t.Fatalf("StartServer: %v", err)
	}
	stopped := false
	stopShare := func() {
		if stopped {
			return
		}
		stopped = true
		_ = server.Close(context.Background())
		_ = source.Close()
	}
	defer stopShare()

	code := relay.ShareCode{
		Version: 1, Host: "127.0.0.1", Port: server.Port(),
		ShareID: shareID, Token: shareToken,
		Fingerprint: identity.Fingerprint, Name: "公司 VPN",
	}

	// ---- B: importing client --------------------------------------------
	bPoint := model.AccessPoint{
		ID: "b1", Name: "同事分享", Protocol: model.ProtocolLANRelay,
		Server: code.Host, Port: code.Port, InPool: true,
		Relay: &model.RelayPointOptions{
			Version: 1, ShareID: code.ShareID, CertificateSHA256: code.Fingerprint,
		},
	}
	bCfg := testConfig(bPoint)
	var savedSnapshots int
	var saved *workeripc.ResourceSnapshot
	bConnector := NewRelayConnector(RelayConnectorOptions{
		Dial: relay.DirectDialer,
		SaveSnapshot: func(pointID string, resources *workeripc.ResourceSnapshot) error {
			savedSnapshots++
			saved = resources
			return nil
		},
	})
	bMgr := NewManager(bConnector, func(id string) (Credentials, error) {
		return Credentials{Login: code.Token}, nil
	}, NewLogBus(100), nil)
	t.Cleanup(bMgr.Close)
	bMgr.Apply(bCfg)
	bMgr.Connect("b1")
	waitFor(t, "B online", func() bool { online, _, _ := bMgr.Counts(); return online == 1 })
	if savedSnapshots == 0 || saved == nil {
		t.Fatal("the first snapshot must be persisted before the node is announced online")
	}
	if len(saved.IPRules) == 0 {
		t.Fatal("saved attribution is empty")
	}

	// ---- B authorized resource goes through A ---------------------------
	dialed := &dialRecorder{}
	ctx := WithOriginalDial(context.Background(), dialed.dial)
	conn, err := bMgr.dialResource(ctx, "tcp", "10.5.1.2:443")
	if err != nil {
		t.Fatalf("authorized resource failed: %v", err)
	}
	payload := []byte("through-a")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("tunnel payload mismatch: %q", got)
	}
	_ = conn.Close()
	if len(aSess.dials()) != 1 || aSess.dials()[0] != "10.5.1.2:443" {
		t.Fatalf("A saw unexpected dials: %v", aSess.dials())
	}
	if dialed.count() != 0 {
		t.Fatal("an authorized resource must not use B's own network")
	}

	// ---- B ordinary public traffic stays on B ---------------------------
	pubConn, err := bMgr.dialResource(ctx, "tcp", "93.184.216.34:80")
	if err != nil {
		t.Fatalf("public traffic should go direct: %v", err)
	}
	_ = pubConn.Close()
	if dialed.count() != 1 || dialed.last() != "93.184.216.34:80" {
		t.Fatalf("public target did not use B's own network: %v", dialed.all())
	}
	if len(aSess.dials()) != 1 {
		t.Fatalf("A handled B's public traffic: %v", aSess.dials())
	}

	// ---- a target the share owns but does not authorize is refused ------
	// The rule starts at port 443, so 8443 belongs to the share's range yet is
	// not granted: it must be refused instead of sliding to B's network.
	if _, err := bMgr.dialResource(ctx, "tcp", "10.5.1.2:8443"); err == nil {
		t.Fatal("an unauthorized port must be refused, not dialed")
	}
	if dialed.count() != 1 {
		t.Fatalf("a refused target leaked to B's direct path: %v", dialed.all())
	}
	if len(aSess.dials()) != 1 {
		t.Fatalf("A saw a request for an unauthorized port: %v", aSess.dials())
	}

	// ---- a target the share does not know at all is B's own traffic -----
	unknown, err := bMgr.dialResource(ctx, "tcp", "10.9.9.9:443")
	if err != nil {
		t.Fatalf("a target unknown to the share stays on B's network: %v", err)
	}
	_ = unknown.Close()
	if dialed.count() != 2 {
		t.Fatalf("unknown target did not use B's own network: %v", dialed.all())
	}
	if len(aSess.dials()) != 1 {
		t.Fatalf("A handled a target outside its share: %v", aSess.dials())
	}

	// ---- revocation closes a live tunnel --------------------------------
	live, err := bMgr.dialResource(ctx, "tcp", "10.5.1.3:443")
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	if _, err := live.Write([]byte("live")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(live, make([]byte, 4)); err != nil {
		t.Fatal(err)
	}
	stopShare()
	_ = live.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := live.Read(make([]byte, 1)); err == nil {
		t.Fatal("live tunnel survived 关闭共享")
	}

	// ---- known attribution never falls back to direct -------------------
	// Force B's session to observe the loss, as the watcher would.
	bMgr.mu.RLock()
	ep := bMgr.points["b1"]
	sess := ep.sess
	bMgr.mu.RUnlock()
	if sess != nil {
		_ = sess.Close()
	}
	waitFor(t, "B offline", func() bool {
		bMgr.mu.RLock()
		defer bMgr.mu.RUnlock()
		cur := bMgr.points["b1"]
		return cur == nil || cur.state != StateOnline
	})
	decision := bMgr.PreviewRoute(routing.Request{Network: "tcp", Address: "10.5.1.2:443", Entry: "统一代理"})
	if decision.Action == "direct" {
		t.Fatalf("a known managed target fell back to direct after the share ended: %+v", decision)
	}
	before := dialed.count()
	if _, err := bMgr.dialResource(ctx, "tcp", "10.5.1.2:443"); err == nil {
		t.Fatal("a known managed target was dialed after the share ended")
	}
	if dialed.count() != before {
		t.Fatal("a known managed target leaked to B's own network")
	}
}

type dialRecorder struct {
	mu      sync.Mutex
	targets []string
}

func (d *dialRecorder) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.targets = append(d.targets, addr)
	d.mu.Unlock()
	a, b := net.Pipe()
	go func() { _ = b.Close() }()
	return a, nil
}

func (d *dialRecorder) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.targets)
}

func (d *dialRecorder) last() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.targets) == 0 {
		return ""
	}
	return d.targets[len(d.targets)-1]
}

func (d *dialRecorder) all() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.targets...)
}

// TestRelayHistoryGateBlocksUnknownTargets covers the history-protection gate:
// when a relay node's attribution cannot be verified, an unknown target must not
// silently use the original network while another gateway's resources still work.
func TestRelayHistoryGateBlocksUnknownTargets(t *testing.T) {
	cfg := sharePointConfig()
	m := newTestManager(t, (&fakeConnector{}).Connect, cfg)
	m.SetRelayHistoryUnverified(true)
	dialed := &dialRecorder{}
	ctx := WithOriginalDial(context.Background(), dialed.dial)
	if _, err := m.dialResource(ctx, "tcp", "203.0.113.9:443"); err == nil {
		t.Fatal("unknown target went direct while the history gate was on")
	}
	if dialed.count() != 0 {
		t.Fatal("unknown target reached the original network")
	}
	m.SetRelayHistoryUnverified(false)
	conn, err := m.dialResource(ctx, "tcp", "203.0.113.9:443")
	if err != nil {
		t.Fatalf("gate off should allow direct: %v", err)
	}
	_ = conn.Close()
	if dialed.count() != 1 {
		t.Fatal("gate off did not use the original network")
	}
}

// TestSeedRelayKnownOnlyBlocksDirect proves the cache is attribution, never
// authorization: a seeded target is refused as a dial but stops being "direct".
func TestSeedRelayKnownOnlyBlocksDirect(t *testing.T) {
	cfg := testConfig(model.AccessPoint{
		ID: "b1", Name: "同事分享", Protocol: model.ProtocolLANRelay,
		Server: "192.168.1.50", Port: 23456, InPool: true,
	})
	m := newTestManager(t, (&fakeConnector{}).Connect, cfg)
	m.SeedRelayKnown("b1", corpResources())
	decision := m.PreviewRoute(routing.Request{Network: "tcp", Address: "10.5.1.2:443", Entry: "统一代理"})
	if decision.Action == "direct" {
		t.Fatalf("seeded attribution must not resolve to direct: %+v", decision)
	}
	dialed := &dialRecorder{}
	ctx := WithOriginalDial(context.Background(), dialed.dial)
	if _, err := m.dialResource(ctx, "tcp", "10.5.1.2:443"); err == nil {
		t.Fatal("seeded attribution authorized a dial")
	}
	if dialed.count() != 0 {
		t.Fatal("seeded attribution leaked to the original network")
	}
}
