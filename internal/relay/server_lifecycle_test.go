package relay

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// review helpers: deterministic waiting instead of fixed sleeps.

func waitRelay(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

func (f *shareFixture) committedEpoch() uint64 {
	f.server.snapMu.Lock()
	defer f.server.snapMu.Unlock()
	return f.server.snap.Epoch
}

// expectClosed asserts the tunnel no longer carries data.
func expectClosed(t *testing.T, conn net.Conn, what string) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	var buf [4]byte
	for attempts := 0; attempts < 100; attempts++ {
		if _, err := conn.Write([]byte("ping")); err != nil {
			return
		}
		if _, err := io.ReadFull(conn, buf[:]); err != nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s: tunnel still carries traffic", what)
}

func expectOpen(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("tunnel is not usable: %v", err)
	}
	var buf [4]byte
	if _, err := io.ReadFull(conn, buf[:]); err != nil {
		t.Fatalf("tunnel is not usable: %v", err)
	}
	if string(buf[:]) != "ping" {
		t.Fatalf("unexpected tunnel echo %q", buf[:])
	}
	_ = conn.SetDeadline(time.Time{})
}

// nextGeneration builds a snapshot that adds a second authorized range.
func nextGeneration() SourceSnapshot {
	next := testSnapshot()
	next.Epoch = 2
	next.Resources.IPRules = append(next.Resources.IPRules, IPRule{Min: "10.9.0.0", Max: "10.9.0.255", PortMin: 443, PortMax: 443, Protocol: "tcp"})
	next.Resources.Normalize()
	next.Revision = next.Resources.Revision(next.Capabilities)
	return next
}

// R3: a resource change retired the whole connection table permanently, so
// every later CONNECT was refused with share_closed until the share was
// restarted.
func TestResourceChangeKeepsServingTheNewGeneration(t *testing.T) {
	fx := startShareFixture(t, "review-token")
	client := fx.client(t)
	ctx := context.Background()
	state, token, err := client.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	old, err := client.Dial(ctx, token, state.Epoch, state.Revision, "10.1.2.3:443")
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	expectOpen(t, old)

	fx.source.setSnapshot(nextGeneration())
	waitRelay(t, "the server commits the new generation", func() bool { return fx.committedEpoch() == 2 })

	// The old generation's tunnel is gone...
	expectClosed(t, old, "after a resource change")

	// ...but the new generation still accepts authorized work.
	status, err := client.Status(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	if status.Epoch != 2 {
		t.Fatalf("status epoch = %d, want 2", status.Epoch)
	}
	fresh, err := client.Dial(ctx, token, status.Epoch, status.Revision, "10.1.2.3:443")
	if err != nil {
		t.Fatalf("new generation is authorized but CONNECT failed: %v", err)
	}
	defer fresh.Close()
	expectOpen(t, fresh)

	// A second change can be used the same way: the table is not one-shot.
	fx.source.setSnapshot(func() SourceSnapshot {
		third := nextGeneration()
		third.Epoch = 3
		third.Resources.Normalize()
		third.Revision = third.Resources.Revision(third.Capabilities)
		return third
	}())
	waitRelay(t, "the server commits the third generation", func() bool { return fx.committedEpoch() == 3 })
	status, err = client.Status(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	again, err := client.Dial(ctx, token, status.Epoch, status.Revision, "10.1.2.3:443")
	if err != nil {
		t.Fatalf("a later generation is authorized but CONNECT failed: %v", err)
	}
	again.Close()
}

// R4: the change watch compared two reads taken after the notification, so an
// expired cache made revocation look like a no-op and the withdrawn target kept
// an established tunnel.
func TestResourceChangeClosesTunnelsWhenCacheExpired(t *testing.T) {
	fx := startShareFixture(t, "review-token")
	client := fx.client(t)
	ctx := context.Background()
	state, token, err := client.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := client.Dial(ctx, token, state.Epoch, state.Revision, "10.1.2.3:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	expectOpen(t, conn)

	// The cached generation is stale, which used to make the "before" read
	// return the new snapshot.
	fx.server.snapMu.Lock()
	fx.server.snapAt = time.Now().Add(-time.Second)
	fx.server.snapMu.Unlock()

	revoked := nextGeneration()
	revoked.Resources.IPRules = revoked.Resources.IPRules[1:] // drop the 10.1 range
	revoked.Resources.Normalize()
	revoked.Revision = revoked.Resources.Revision(revoked.Capabilities)
	fx.source.setSnapshot(revoked)
	waitRelay(t, "the server commits the revocation", func() bool { return fx.committedEpoch() == 2 })

	expectClosed(t, conn, "after the target was withdrawn")
	// The withdrawn target is refused, not silently re-authorized.
	if _, err := client.Dial(ctx, token, 2, revoked.Revision, "10.1.2.3:443"); err == nil {
		t.Fatal("a withdrawn target was still dialable")
	}
}

// R5: expiring a lease only deleted the authentication record, so the tunnels
// that lease had already opened kept working with no live client at all.
func TestExpiredLeaseClosesItsTunnels(t *testing.T) {
	fx := startShareFixture(t, "review-token")
	client := fx.client(t)
	ctx := context.Background()
	state, token, err := client.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := client.Dial(ctx, token, state.Epoch, state.Revision, "10.1.2.3:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	expectOpen(t, conn)

	fx.server.clients.mu.Lock()
	c := fx.server.clients.byToken[token]
	if c == nil {
		fx.server.clients.mu.Unlock()
		t.Fatal("the lease was already gone")
	}
	c.expires = time.Now().Add(-time.Second)
	fx.server.clients.mu.Unlock()

	// The production expiry path, not a test-only shortcut.
	if n := fx.server.ActiveClients(); n != 0 {
		t.Fatalf("active clients = %d after expiry, want 0", n)
	}
	expectClosed(t, conn, "after the lease expired")

	// The token is dead for control requests too.
	if _, err := client.Status(ctx, token); err == nil {
		t.Fatal("an expired lease still renews")
	}
}

// R5: deleting a session revoked the token but used to leave its tunnels open.
func TestDeletedSessionClosesItsTunnels(t *testing.T) {
	fx := startShareFixture(t, "review-token")
	client := fx.client(t)
	ctx := context.Background()
	state, token, err := client.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := client.Dial(ctx, token, state.Epoch, state.Revision, "10.1.2.3:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	expectOpen(t, conn)
	if err := client.Revoke(ctx, token); err != nil {
		t.Fatal(err)
	}
	expectClosed(t, conn, "after the session was revoked")
}

// A completely stopped share must keep refusing: the revertible-generations
// change must not resurrect a share that was closed.
func TestPermanentStopStillRefusesAfterAChange(t *testing.T) {
	fx := startShareFixture(t, "review-token")
	client := fx.client(t)
	ctx := context.Background()
	state, token, err := client.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fx.server.RevokeAll()
	fx.source.setSnapshot(nextGeneration())
	time.Sleep(50 * time.Millisecond)
	if _, err := client.Dial(ctx, token, state.Epoch, state.Revision, "10.1.2.3:443"); err == nil {
		t.Fatal("a revoked share accepted a new tunnel")
	}
	waitRelay(t, "the share lifecycle is cancelled", func() bool { return fx.server.root.Err() != nil })
}

// blockingDialSource holds every dial until the caller's context is cancelled,
// so a revocation can be observed while the upstream dial is still pending.
type blockingDialSource struct {
	*fakeSource
	started chan struct{}
	once    sync.Once
}

func (s *blockingDialSource) DialVPN(ctx context.Context, revision, target string) (net.Conn, error) {
	s.once.Do(func() { close(s.started) })
	<-ctx.Done()
	return nil, ctx.Err()
}

// R5: revoking a lease must abort that client's pending dial, not let it turn
// into a tunnel after the credential is gone.
func TestRevokedLeaseCancelsAPendingDial(t *testing.T) {
	blocking := &blockingDialSource{started: make(chan struct{})}
	fx := startShareFixtureWith(t, "review-token", func(f *fakeSource) Source {
		blocking.fakeSource = f
		return blocking
	})
	client := fx.client(t)
	ctx := context.Background()
	state, token, err := client.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	dialErr := make(chan error, 1)
	go func() {
		_, err := client.Dial(ctx, token, state.Epoch, state.Revision, "10.1.2.3:443")
		dialErr <- err
	}()
	<-blocking.started
	// Expire the lease the way the sweep would, then let the production
	// expiry path run; the pending dial must end with it.
	fx.server.clients.mu.Lock()
	fx.server.clients.byToken[token].expires = time.Now().Add(-time.Second)
	fx.server.clients.mu.Unlock()
	fx.server.ActiveClients()
	select {
	case err := <-dialErr:
		if err == nil {
			t.Fatal("the pending dial succeeded after its lease was revoked")
		}
		var re *Error
		if errors.As(err, &re) && re.Code == CodeResourceDenied {
			t.Fatal("the dial reached the VPN source after revocation")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the pending dial was not cancelled by the lease revocation")
	}
}
