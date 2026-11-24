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
