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
	// release, when set, lets a test complete the dial deliberately; otherwise
	// the dial only ends when its context is cancelled.
	release chan struct{}
}

func (s *blockingDialSource) DialVPN(ctx context.Context, revision, target string) (net.Conn, error) {
	s.once.Do(func() { close(s.started) })
	if s.release != nil {
		select {
		case <-s.release:
			return s.fakeSource.DialVPN(ctx, revision, target)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
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

// R4: a client request that reads the new generation before the change watcher
// does must perform the same revocation, not just return the new epoch.
func TestClientRefreshCommitsTheGenerationAndRevokes(t *testing.T) {
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

	// A new snapshot becomes visible to the source. The cache is stale, so the
	// very next request is what discovers it — before the watcher runs.
	fx.server.snapMu.Lock()
	fx.server.snapAt = time.Now().Add(-time.Second)
	fx.server.snapMu.Unlock()
	fx.source.setSnapshot(nextGeneration())

	status, err := client.Status(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	if status.Epoch != 2 {
		t.Fatalf("status epoch = %d, want 2", status.Epoch)
	}
	expectClosed(t, conn, "after a client refresh committed the new generation")
}

// R4: while the cached generation is still fresh, no revocation happens (nothing
// changed), and the request keeps answering from the committed snapshot.
func TestFreshCacheKeepsTheCommittedGeneration(t *testing.T) {
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
	status, err := client.Status(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	if status.Epoch != 1 || status.Revision != state.Revision {
		t.Fatalf("a fresh cache changed the generation: %+v", status)
	}
	expectOpen(t, conn)
}

// R3: a dial that completes after its generation was retired must not become a
// tunnel, and its slot must come back.
func TestDialCompletingAfterAGenerationChangeIsDropped(t *testing.T) {
	blocking := &blockingDialSource{started: make(chan struct{})}
	release := make(chan struct{})
	fx := startShareFixtureWith(t, "review-token", func(f *fakeSource) Source {
		blocking.fakeSource = f
		blocking.release = release
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
	fx.source.setSnapshot(nextGeneration())
	waitRelay(t, "the server commits the new generation", func() bool { return fx.committedEpoch() == 2 })
	close(release)
	select {
	case err := <-dialErr:
		if err == nil {
			t.Fatal("a dial under the retired generation succeeded")
		}
		var re *Error
		if errors.As(err, &re) && re.Code != CodeStaleResources && re.Code != CodeShareClosed {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the stale dial never returned")
	}
	waitRelay(t, "the connection slot is released", func() bool { return fx.server.conns.count() == 0 })
}

// R5: an expired lease must return its connection slots, not leak them.
func TestExpiredLeaseReleasesConnectionSlots(t *testing.T) {
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
	fx.server.clients.mu.Lock()
	fx.server.clients.byToken[token].expires = time.Now().Add(-time.Second)
	fx.server.clients.mu.Unlock()
	fx.server.ActiveClients()
	expectClosed(t, conn, "after the lease expired")
	waitRelay(t, "the slot is released", func() bool { return fx.server.conns.count() == 0 })
}

// R5: re-authenticating the same instance replaces the lease, and the old token's
// tunnels die with it.
func TestReauthenticationClosesTheOldTokenTunnels(t *testing.T) {
	fx := startShareFixture(t, "review-token")
	rc := fx.client(t)
	ctx := context.Background()
	state, token, err := rc.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := rc.Dial(ctx, token, state.Epoch, state.Revision, "10.1.2.3:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	expectOpen(t, conn)

	fx.server.clients.mu.Lock()
	id := fx.server.clients.byToken[token].id
	fx.server.clients.mu.Unlock()
	replaced := fx.server.clients.replace(id, "again", "new-token", time.Now())
	fx.server.clients.revoke([]*client{replaced})
	expectClosed(t, conn, "after the instance re-authenticated")
	if fx.server.clients.lookup(token, time.Now()) != nil {
		t.Fatal("the replaced token is still valid")
	}
}

// R5: one client's expiry must not disturb another client's tunnel.
func TestExpiringOneLeaseLeavesOtherClientsAlone(t *testing.T) {
	fx := startShareFixture(t, "review-token")
	ctx := context.Background()
	first := fx.client(t)
	second := fx.client(t)
	stateA, tokenA, err := first.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stateB, tokenB, err := second.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	connA, err := first.Dial(ctx, tokenA, stateA.Epoch, stateA.Revision, "10.1.2.3:443")
	if err != nil {
		t.Fatal(err)
	}
	defer connA.Close()
	connB, err := second.Dial(ctx, tokenB, stateB.Epoch, stateB.Revision, "10.1.2.4:443")
	if err != nil {
		t.Fatal(err)
	}
	defer connB.Close()
	expectOpen(t, connA)
	expectOpen(t, connB)

	fx.server.clients.mu.Lock()
	fx.server.clients.byToken[tokenA].expires = time.Now().Add(-time.Second)
	fx.server.clients.mu.Unlock()
	fx.server.ActiveClients()
	expectClosed(t, connA, "after its lease expired")
	expectOpen(t, connB)
}

// R5: a renewal that races an expiry must not bring a dead lease back.
func TestTouchCannotReviveAnExpiredLease(t *testing.T) {
	registry := newClientRegistry(4, time.Minute)
	now := time.Now()
	c, err := registry.create("id", "name", "token", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := registry.touch(c, now); !ok {
		t.Fatal("a live lease could not renew")
	}
	// The lease expires, then a late renewal arrives.
	if _, ok := registry.touch(c, now.Add(2*time.Minute)); ok {
		t.Fatal("an expired lease was revived by a renewal")
	}
	if registry.lookup("token", now.Add(2*time.Minute)) != nil {
		t.Fatal("an expired lease stayed valid")
	}
	// A replaced lease cannot be renewed either.
	c2, err := registry.create("id2", "name", "token2", now)
	if err != nil {
		t.Fatal(err)
	}
	registry.replace("id2", "name", "token3", now)
	if _, ok := registry.touch(c2, now); ok {
		t.Fatal("a replaced lease renewed itself")
	}
}
