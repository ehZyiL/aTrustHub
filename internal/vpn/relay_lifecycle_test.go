package vpn

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/ehzyil/connect-hub/internal/relay"
	"github.com/ehzyil/connect-hub/internal/routing"
	"github.com/ehzyil/connect-hub/internal/store"
	"github.com/ehzyil/connect-hub/internal/workeripc"
)

// R1: a session that ends must leave Online without waiting for a resource
// update. The review's reproducer: consumeUpdates ran synchronously before
// watch, so a healthy Updates channel kept Done from ever being observed.
func TestDeadRelaySessionLeavesOnlineWithoutUpdates(t *testing.T) {
	code := relay.ShareCode{Version: 1, Host: "192.168.1.50", Port: 12345, Fingerprint: strings.Repeat("ab", 32)}
	c, err := relay.NewClient(relay.ClientOptions{Code: code})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sess := &relaySession{client: c, done: make(chan struct{}), updates: make(chan SessionUpdate), ctx: ctx, cancel: cancel}
	m := newTestManager(t, func(context.Context, model.AccessPoint, Credentials) (Session, error) {
		return sess, nil
	}, testConfig(model.AccessPoint{ID: "r1", Name: "relay", Protocol: model.ProtocolLANRelay, Server: "192.168.1.50", Port: 12345, InPool: true}))
	m.Connect("r1")
	waitFor(t, "online", func() bool { v, _ := m.View("r1"); return v.State == StateOnline })

	sess.fail(relay.NewError(relay.CodeShareClosed, "closed"))
	waitFor(t, "offline after the session ended", func() bool {
		v, _ := m.View("r1")
		return v.State != StateOnline
	})
}

// R6: the friendly wording replaced the typed error with errors.New, so a
// terminal share failure looked reconnectable again.
func TestFriendlyRelayErrorKeepsTerminalClassification(t *testing.T) {
	terminal := []relay.Code{relay.CodeShareClosed, relay.CodeInvalidCredentials, relay.CodeProtocolUnsupported}
	for _, code := range terminal {
		friendly := friendlyRelayError(relay.NewError(code, "raw"))
		if RelayReconnectable(friendly) {
			t.Fatalf("%s became reconnectable after presentation: %v", code, friendly)
		}
		var re *relay.Error
		if !errors.As(friendly, &re) || re.Code != code {
			t.Fatalf("%s lost its type through presentation: %v", code, friendly)
		}
		if strings.Contains(friendly.Error(), "raw") {
			t.Fatalf("%s still shows the protocol text: %v", code, friendly)
		}
	}
	// Transient failures must keep their bounded reconnect budget.
	if !RelayReconnectable(friendlyRelayError(relay.NewError(relay.CodeVPNUnavailable, "broken pipe"))) {
		t.Fatal("a transient share error stopped being reconnectable")
	}
	// A plain error is not a share error and keeps the old behaviour.
	if !RelayReconnectable(errors.New("dial failed")) {
		t.Fatal("plain errors must stay reconnectable")
	}
}

// updaterSession publishes resource snapshots on demand.
type updaterSession struct {
	*fakeSession
	updates chan SessionUpdate
}

func (s *updaterSession) Updates() <-chan SessionUpdate { return s.updates }

// R7: the endpoint kept the previous session's update sequence, so the first
// snapshot of the new session (which restarts at 1) was discarded and the
// manager stayed on the pre-reconnect resources.
func TestReconnectResetsUpdateSequence(t *testing.T) {
	point := model.AccessPoint{ID: "r1", Name: "relay", Protocol: model.ProtocolLANRelay, Server: "192.168.1.50", Port: 12345, InPool: true}
	var mu sync.Mutex
	sessions := make([]*updaterSession, 0, 2)
	m := newTestManager(t, func(context.Context, model.AccessPoint, Credentials) (Session, error) {
		s := &updaterSession{fakeSession: newFakeSession("r1"), updates: make(chan SessionUpdate, 4)}
		mu.Lock()
		sessions = append(sessions, s)
		mu.Unlock()
		return s, nil
	}, testConfig(point))

	first := func() *workeripc.ResourceSnapshot {
		return &workeripc.ResourceSnapshot{Tunnel: "ipv4-l3", IPRules: []workeripc.IPRule{{Min: "10.1.0.0", Max: "10.1.255.255", PortMin: 443, PortMax: 443, Protocol: "tcp"}}}
	}
	second := func() *workeripc.ResourceSnapshot {
		return &workeripc.ResourceSnapshot{Tunnel: "ipv4-l3", IPRules: []workeripc.IPRule{{Min: "10.2.0.0", Max: "10.2.255.255", PortMin: 443, PortMax: 443, Protocol: "tcp"}}}
	}

	m.Connect("r1")
	waitFor(t, "first session online", func() bool { v, _ := m.View("r1"); return v.State == StateOnline })
	mu.Lock()
	s1 := sessions[0]
	mu.Unlock()
	s1.updates <- SessionUpdate{Sequence: 2, Info: SessionInfo{Resources: first()}}
	waitFor(t, "first snapshot applied", func() bool { return hasRule(m, "r1", "10.1.0.0") })

	m.Disconnect("r1")
	waitFor(t, "offline", func() bool { v, _ := m.View("r1"); return v.State == StateOffline })

	m.Connect("r1")
	waitFor(t, "second session online", func() bool {
		mu.Lock()
		defer mu.Unlock()
		v, _ := m.View("r1")
		return len(sessions) == 2 && v.State == StateOnline
	})
	mu.Lock()
	s2 := sessions[1]
	mu.Unlock()
	// The new session starts its own sequence at 1; the first snapshot it
	// publishes reuses the number the old session had already accepted.
	s2.updates <- SessionUpdate{Sequence: 2, Info: SessionInfo{Resources: second()}}
	waitFor(t, "new session's first snapshot applied", func() bool { return hasRule(m, "r1", "10.2.0.0") })

	// A late event from the old session cannot move the new cursor or rules.
	m.applyUpdate("r1", 1, s1, SessionUpdate{Sequence: 100, Info: SessionInfo{Resources: first()}})
	if hasRule(m, "r1", "10.1.0.0") {
		t.Fatal("a late update from the previous session polluted the current resources")
	}
	// The new session keeps accepting increasing sequences and rejects repeats.
	s2.updates <- SessionUpdate{Sequence: 3, Info: SessionInfo{Resources: first()}}
	waitFor(t, "third snapshot applied", func() bool { return hasRule(m, "r1", "10.1.0.0") })
	// A duplicate or out-of-order update on the same session is dropped.
	s2.updates <- SessionUpdate{Sequence: 2, Info: SessionInfo{Resources: second()}}
	time.Sleep(50 * time.Millisecond)
	if hasRule(m, "r1", "10.2.0.0") {
		t.Fatal("a repeated sequence number replaced the newer snapshot")
	}
}

func hasRule(m *Manager, id, prefix string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ep := m.points[id]
	if ep == nil || ep.info.Resources == nil {
		return false
	}
	for _, r := range ep.info.Resources.IPRules {
		if strings.HasPrefix(r.Min, prefix) {
			return true
		}
	}
	return false
}

// R1 (cleanup half): fail must still be reaped by the Manager's Close, not
// return early because the session already marked itself closed.
func TestFailedRelaySessionIsStillReaped(t *testing.T) {
	code := relay.ShareCode{Version: 1, Host: "192.168.1.50", Port: 12345, Fingerprint: strings.Repeat("ab", 32)}
	c, err := relay.NewClient(relay.ClientOptions{Code: code})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sess := &relaySession{client: c, done: make(chan struct{}), updates: make(chan SessionUpdate, 4), ctx: ctx, cancel: cancel}
	sess.fail(relay.NewError(relay.CodeShareClosed, "closed"))
	// Close after fail must finish cleanup instead of returning early.
	done := make(chan struct{})
	go func() {
		_ = sess.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Close blocked after fail")
	}
	select {
	case _, open := <-sess.updates:
		if open {
			t.Fatal("unexpected update after the session ended")
		}
	case <-time.After(time.Second):
		t.Fatal("the update stream was never closed after fail")
	}
}

// R2: history must survive a later, smaller snapshot. The review's reproducer:
// saving an empty snapshot erased the previously owned range, so a restart
// treated the old VPN target as an ordinary direct connection.
func TestHistoryRetainsWithdrawnOwnershipAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir, store.NewMemorySecrets())
	if err != nil {
		t.Fatal(err)
	}
	point := model.AccessPoint{
		ID: "r1", Name: "relay", Protocol: model.ProtocolLANRelay, Server: "192.168.1.50", Port: 12345, InPool: true,
		Relay: &model.RelayPointOptions{Version: 1, ShareID: "share-identity-1", CertificateSHA256: strings.Repeat("ab", 32)},
	}
	if _, err := st.Update(func(cfg *model.Config) error { cfg.Add(point); return nil }); err != nil {
		t.Fatal(err)
	}
	source := store.RelaySource{ShareID: point.Relay.ShareID, Fingerprint: point.Relay.CertificateSHA256}
	if err := st.SaveRelayKnown(point.ID, source, corpResources()); err != nil {
		t.Fatal(err)
	}
	// The host withdraws the range, and the smaller snapshot is what gets saved.
	if err := st.SaveRelayKnown(point.ID, source, &workeripc.ResourceSnapshot{Tunnel: "ipv4-l3"}); err != nil {
		t.Fatal(err)
	}
	known, err := st.LoadRelayKnown(point.ID)
	if err != nil {
		t.Fatal(err)
	}
	m := newTestManager(t, (&fakeConnector{}).Connect, testConfig(point))
	m.SeedRelayKnown(point.ID, known.Resources)
	d := m.PreviewRoute(routing.Request{Network: "tcp", Address: "10.5.1.2:443", Entry: "统一代理"})
	if d.Action == "direct" {
		t.Fatalf("previously owned, then withdrawn resource falls back to direct after reload: %+v", d)
	}
}

// R2: repairing one node must not unprotect the others, and the gate only lifts
// once every relay node has verified attribution again.
func TestSeedingARepairedNodeUnblocksOnlyThatNode(t *testing.T) {
	cfg := testConfig(
		model.AccessPoint{ID: "r1", Name: "分享一", Protocol: model.ProtocolLANRelay, Server: "192.168.1.50", Port: 1, InPool: true},
		model.AccessPoint{ID: "r2", Name: "分享二", Protocol: model.ProtocolLANRelay, Server: "192.168.1.51", Port: 2, InPool: true},
	)
	m := newTestManager(t, (&fakeConnector{}).Connect, cfg)
	m.BlockRelayAutoConnect("r1", true)
	m.BlockRelayAutoConnect("r2", true)
	if !m.RelayHistoryUnverified() {
		t.Fatal("the gate must be on while both nodes are unverified")
	}
	m.SeedRelayKnown("r1", corpResources())
	if m.RelayAutoConnectBlocked("r1") {
		t.Fatal("the repaired node stayed out of the auto-connect set")
	}
	if !m.RelayAutoConnectBlocked("r2") || !m.RelayHistoryUnverified() {
		t.Fatal("repairing one node unblocked the other or lifted the gate")
	}
	m.SeedRelayKnown("r2", corpResources())
	if m.RelayHistoryUnverified() {
		t.Fatal("the gate stayed on after every node was repaired")
	}
}

// R1 (leak half): detaching a session cancels its monitor, so no goroutine waits
// forever on a channel that will never close.
func TestSessionMonitorStopsWhenTheSessionIsDetached(t *testing.T) {
	point := model.AccessPoint{ID: "r1", Name: "relay", Protocol: model.ProtocolLANRelay, Server: "192.168.1.50", Port: 12345, InPool: true}
	var mu sync.Mutex
	var installed *updaterSession
	m := newTestManager(t, func(context.Context, model.AccessPoint, Credentials) (Session, error) {
		s := &updaterSession{fakeSession: newFakeSession("r1"), updates: make(chan SessionUpdate, 1)}
		mu.Lock()
		installed = s
		mu.Unlock()
		return s, nil
	}, testConfig(point))
	m.Connect("r1")
	waitFor(t, "online", func() bool { v, _ := m.View("r1"); return v.State == StateOnline })
	m.mu.RLock()
	stop := m.points["r1"].sessStop
	m.mu.RUnlock()
	if stop == nil {
		t.Fatal("no monitor lifetime was installed for the session")
	}
	m.Disconnect("r1")
	m.mu.RLock()
	stillInstalled := m.points["r1"].sessStop != nil
	m.mu.RUnlock()
	if stillInstalled {
		t.Fatal("the monitor lifetime of a detached session was not cancelled")
	}
	// A late update from the detached session changes nothing.
	mu.Lock()
	s := installed
	mu.Unlock()
	s.updates <- SessionUpdate{Sequence: 1, Info: SessionInfo{Resources: corpResources()}}
	if hasRule(m, "r1", "10.5.0.0") {
		t.Fatal("a detached session still published resources")
	}
}

// R1 + R6 on the real path: a revoked share token ends a live relay session with
// a typed terminal error, and the manager must not schedule an automatic retry.
func TestRealShareRevocationDoesNotAutoReconnect(t *testing.T) {
	aSess := &echoStrictSession{fakeSession: newFakeSession("a1"), allow: "10.5."}
	aSess.info.Resources = corpResources()
	aMgr := newTestManager(t, func(context.Context, model.AccessPoint, Credentials) (Session, error) {
		return aSess, nil
	}, testConfig(model.AccessPoint{ID: "a1", Name: "公司 VPN", Protocol: model.ProtocolATrust, Server: "vpn.example.com", Port: 443, Username: "u", InPool: true}))
	aMgr.Connect("a1")
	waitFor(t, "A online", func() bool { online, _, _ := aMgr.Counts(); return online == 1 })
	source, err := aMgr.AcquireRelayShareSource("a1")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := relay.GenerateIdentity("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	shareID, shareToken := randomB64(16), randomB64(32)
	server, err := relay.StartServer(relay.ServerOptions{
		Identity: identity, Source: source, Token: shareToken,
		ShareID: shareID, ServerInstanceID: "a-instance", Port: 0, Lease: 15 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = server.Close(context.Background())
		_ = source.Close()
	}()
	code := relay.ShareCode{Version: 1, Host: "127.0.0.1", Port: server.Port(), ShareID: shareID, Token: shareToken, Fingerprint: identity.Fingerprint}

	point := model.AccessPoint{
		ID: "b1", Name: "同事分享", Protocol: model.ProtocolLANRelay,
		Server: code.Host, Port: code.Port, InPool: true, AutoConnect: false,
		Relay: &model.RelayPointOptions{Version: 1, ShareID: shareID, CertificateSHA256: identity.Fingerprint},
	}
	cfg := testConfig(point)
	cfg.Settings.AutoReconnect = true
	var mu sync.Mutex
	attempts := 0
	connector := NewRelayConnector(RelayConnectorOptions{
		Dial:         relay.DirectDialer,
		SaveSnapshot: func(string, RelaySnapshotSource, *workeripc.ResourceSnapshot) error { return nil },
	})
	bMgr := NewManager(func(ctx context.Context, p model.AccessPoint, creds Credentials) (Session, error) {
		mu.Lock()
		attempts++
		mu.Unlock()
		return connector(ctx, p, creds)
	}, func(string) (Credentials, error) { return Credentials{Login: code.Token}, nil }, NewLogBus(100), nil)
	t.Cleanup(bMgr.Close)
	bMgr.Apply(cfg)
	bMgr.reconnectDelay = 20 * time.Millisecond
	bMgr.Connect("b1")
	waitFor(t, "B online", func() bool { v, _ := bMgr.View("b1"); return v.State == StateOnline })

	// A terminal revocation: the share host drops the client lease.
	server.RevokeAll()
	// The heartbeat interval is 5s, so this has to outlast one beat.
	deadline := time.Now().Add(20 * time.Second)
	for {
		view, _ := bMgr.View("b1")
		if view.State != StateOnline {
			t.Logf("B left Online with: %s", view.Error)
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a revoked share left B Online")
		}
		time.Sleep(50 * time.Millisecond)
	}
	view, _ := bMgr.View("b1")
	if view.State != StateError {
		t.Fatalf("state = %s, want Error", view.State)
	}
	// Give the bounded reconnect policy more than enough time to run if it were
	// going to.
	time.Sleep(400 * time.Millisecond)
	mu.Lock()
	got := attempts
	mu.Unlock()
	if got != 1 {
		t.Fatalf("a revoked share was retried %d times", got)
	}
}
