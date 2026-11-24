package vpn

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/ehzyil/connect-hub/internal/relay"
	"github.com/ehzyil/connect-hub/internal/workeripc"
)

// shareForStaleTest is A: a manager standing in for the sharing host plus a real
// relay server, so B's session can be driven exactly like production.
func shareForStaleTest(t *testing.T) (*Manager, *relay.Client, string, *relay.SessionState, relay.ShareCode) {
	t.Helper()
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
	shareID, token := randomB64(16), randomB64(32)
	server, err := relay.StartServer(relay.ServerOptions{
		Identity: identity, Source: source, Token: token,
		ShareID: shareID, ServerInstanceID: "a-instance", Port: 0, Lease: 15 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = server.Close(context.Background())
		_ = source.Close()
	})
	code := relay.ShareCode{Version: 1, Host: "127.0.0.1", Port: server.Port(), ShareID: shareID, Token: token, Fingerprint: identity.Fingerprint, Name: "公司 VPN"}
	client, err := relay.NewClient(relay.ClientOptions{Code: code})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	state, clientToken, err := client.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return aMgr, client, clientToken, state, code
}

// Premise for the retry test below: a request that still carries the previous
// revision is refused with stale_resources (the share does not silently accept
// work under a generation it already retired).
func TestShareRefusesAStaleBusinessRequest(t *testing.T) {
	aMgr, client, token, state, _ := shareForStaleTest(t)
	ctx := context.Background()
	conn, err := client.Dial(ctx, token, state.Epoch, state.Revision, "10.5.1.2:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()

	// A publishes a new generation that still authorizes the same target.
	aMgr.mu.Lock()
	ep := aMgr.points["a1"]
	next := corpResources()
	next.IPRules = append(next.IPRules, workeripc.IPRule{Min: "10.6.0.0", Max: "10.6.255.255", PortMin: 443, PortMax: 443, Protocol: "tcp"})
	ep.rawResources = next
	ep.publishResourcesLocked()
	aMgr.mu.Unlock()

	// The session builds its request from the cached snapshot, exactly like
	// relaySession.DialVPN does.
	conn, err = client.Dial(ctx, token, state.Epoch, state.Revision, "10.5.1.2:443")
	if err == nil {
		_ = conn.Close()
		t.Fatal("the test needs the stale generation to be refused first")
	}
	var re *relay.Error
	if !errors.As(err, &re) || re.Code != relay.CodeStaleResources {
		t.Fatalf("expected stale_resources, got %v", err)
	}
}

// Review: relaySession.DialVPN sends the cached revision once. When the share has
// moved on, the server answers stale_resources and the user's request fails until
// the next heartbeat refreshes the snapshot. The session must refresh once and
// retry instead of surfacing a transient generation change as a failure.
func TestRelaySessionRetriesOnceAfterAResourceChange(t *testing.T) {
	aMgr, client, token, state, code := shareForStaleTest(t)
	point := model.AccessPoint{
		ID: "b1", Name: "同事分享", Protocol: model.ProtocolLANRelay,
		Server: code.Host, Port: code.Port, InPool: true,
		Relay: &model.RelayPointOptions{Version: 1, ShareID: code.ShareID, CertificateSHA256: code.Fingerprint},
	}
	connector := NewRelayConnector(RelayConnectorOptions{
		Dial:         relay.DirectDialer,
		SaveSnapshot: func(string, RelaySnapshotSource, *workeripc.ResourceSnapshot) error { return nil },
	})
	// A relay node authenticates with the share code's token, not with the
	// per-client session token used for data requests.
	sess, err := connector(context.Background(), point, Credentials{Login: code.Token})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	if _, err := sess.Dial(context.Background(), "tcp", "10.5.1.2:443"); err != nil {
		t.Fatalf("first dial: %v", err)
	}

	// A publishes a new generation that still authorizes the same target.
	aMgr.mu.Lock()
	ep := aMgr.points["a1"]
	next := corpResources()
	next.IPRules = append(next.IPRules, workeripc.IPRule{Min: "10.6.0.0", Max: "10.6.255.255", PortMin: 443, PortMax: 443, Protocol: "tcp"})
	ep.rawResources = next
	ep.publishResourcesLocked()
	aMgr.mu.Unlock()

	// Wait until the server has committed the new generation, without touching
	// the session's cache (that is what the heartbeat would do).
	deadline := time.Now().Add(5 * time.Second)
	for {
		status, err := client.Status(context.Background(), token)
		if err != nil {
			t.Fatal(err)
		}
		if status.Epoch != state.Epoch {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the server never committed the new generation")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// The cached revision is now stale; the session must recover on its own.
	conn, err := sess.Dial(context.Background(), "tcp", "10.5.1.2:443")
	if err != nil {
		t.Fatalf("a business request right after a resource change failed: %v", err)
	}
	_ = conn.Close()
}
