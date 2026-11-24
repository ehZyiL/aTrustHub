package relay

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakePersistence is the configuration + secret store double.
type fakePersistence struct {
	mu       sync.Mutex
	settings Settings
	secrets  map[string]string
	failSave bool
	failSet  bool
}

func newFakePersistence() *fakePersistence {
	return &fakePersistence{secrets: map[string]string{}}
}

func (p *fakePersistence) ShareSettings() Settings {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.settings
}

func (p *fakePersistence) SaveShareSettings(s Settings) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failSave {
		return errors.New("磁盘写入失败（测试注入）")
	}
	p.settings = s
	if !s.Enabled {
		// Mirror the real adapter: a disabled share has no bound port.
		p.settings.BoundPort = 0
	}
	return nil
}

func (p *fakePersistence) GetSecret(key string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	v, ok := p.secrets[key]
	if !ok {
		return "", errors.New("secret not found")
	}
	return v, nil
}

func (p *fakePersistence) SetSecret(key, value string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failSet {
		return errors.New("凭据库不可用（测试注入）")
	}
	p.secrets[key] = value
	return nil
}

func (p *fakePersistence) DeleteSecret(key string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.secrets, key)
	return nil
}

func (p *fakePersistence) secretCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.secrets)
}

// fakeSink binds access points to fake sources.
type fakeSink struct {
	mu      sync.Mutex
	names   map[string]string
	sources map[string]*fakeSource
	offline bool
	failErr error
	dialed  []string
	echo    string
}

func newFakeSink(names ...string) *fakeSink {
	s := &fakeSink{names: map[string]string{}, sources: map[string]*fakeSource{}}
	for _, n := range names {
		s.names[n] = "接入点 " + n
	}
	return s
}

func (s *fakeSink) AcquireSource(ctx context.Context, id string) (Source, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.names[id]; !ok {
		return nil, ErrPointMissing
	}
	if s.failErr != nil {
		return nil, s.failErr
	}
	if s.offline {
		return nil, ErrPointNotReady
	}
	src := newFakeSource(testSnapshot())
	src.echo = s.echo
	s.sources[id] = src
	return src, nil
}

func (s *fakeSink) PointName(id string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.names[id]
}

func (s *fakeSink) PointExists(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.names[id]
	return ok
}

func (s *fakeSink) setPoint(id, name string) {
	s.mu.Lock()
	if name == "" {
		delete(s.names, id)
	} else {
		s.names[id] = name
	}
	s.mu.Unlock()
}

func (s *fakeSink) setOffline(v bool) {
	s.mu.Lock()
	s.offline = v
	s.mu.Unlock()
}

func (s *fakeSink) currentSource(id string) *fakeSource {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sources[id]
}

// fakeNets is the LAN address provider.
type fakeNets struct {
	mu   sync.Mutex
	list []Interface
}

func (n *fakeNets) LANCandidates() []Interface {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]Interface(nil), n.list...)
}

func (n *fakeNets) set(list ...Interface) {
	n.mu.Lock()
	n.list = list
	n.mu.Unlock()
}

func loopbackNets() *fakeNets {
	return &fakeNets{list: []Interface{{Name: "lo-test", IPv4: "127.0.0.1"}}}
}

func newTestController(t *testing.T, p *fakePersistence, sink *fakeSink, nets *fakeNets) *Controller {
	t.Helper()
	c := NewController(p, sink, nets, nil, nil)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = c.Shutdown(ctx)
	})
	return c
}

func waitState(t *testing.T, c *Controller, want State) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if c.View().State == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("state = %s, want %s (view %+v)", c.View().State, want, c.View())
}

func setupShare(t *testing.T) (*fakePersistence, *fakeSink, *fakeNets, *Controller, string) {
	t.Helper()
	echo, closeEcho := echoServer(t)
	t.Cleanup(closeEcho)
	p := newFakePersistence()
	sink := newFakeSink("p1", "p2")
	sink.echo = echo
	nets := loopbackNets()
	c := newTestController(t, p, sink, nets)
	if err := c.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	return p, sink, nets, c, echo
}

// TestFirstRunIsOff is the "首次默认关闭" requirement: nothing listens and
// nothing is persisted before the user asks.
func TestFirstRunIsOff(t *testing.T) {
	p, _, _, c, _ := setupShare(t)
	view := c.View()
	if view.Enabled || view.State != StateOff {
		t.Fatalf("first run must be off, got %+v", view)
	}
	if _, err := c.ShareCode(); err == nil {
		t.Fatal("a disabled share must not expose a code")
	}
	if p.secretCount() != 0 {
		t.Fatal("first run must not create secrets")
	}
	if p.ShareSettings().Enabled {
		t.Fatal("first run must not persist Enabled")
	}
}

// TestEnableRestartRestore covers: enable stores intent, restart restores the
// same identity/address/port, and the code stays valid.
func TestEnableRestartRestore(t *testing.T) {
	p, sink, nets, c, _ := setupShare(t)
	ctx := context.Background()
	if err := c.Enable(ctx, EnableOptions{PointID: "p1"}); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	view := c.View()
	if view.State != StateRunning {
		t.Fatalf("state = %s, want running", view.State)
	}
	if !p.ShareSettings().Enabled {
		t.Fatal("Enabled must be persisted")
	}
	codeBefore, err := c.ShareCode()
	if err != nil {
		t.Fatalf("ShareCode: %v", err)
	}
	sid := c.Settings().ShareID
	port := view.Port
	if port == 0 {
		t.Fatal("a running share must have a real port")
	}

	// A normal exit keeps the intent and the identity.
	if err := c.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if !p.ShareSettings().Enabled {
		t.Fatal("Shutdown must keep Enabled")
	}

	// Simulate an application restart with the same configuration and secrets.
	c2 := newTestController(t, p, sink, nets)
	if err := c2.Restore(ctx); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	waitState(t, c2, StateRunning)
	codeAfter, err := c2.ShareCode()
	if err != nil {
		t.Fatalf("ShareCode after restore: %v", err)
	}
	if codeAfter != codeBefore {
		t.Fatalf("restore must reuse the same identity, address and port:\n%s\n%s", codeBefore, codeAfter)
	}
	if c2.Settings().ShareID != sid {
		t.Fatal("share ID changed across restart")
	}
	if c2.View().Port != port {
		t.Fatalf("port changed across restart: %d != %d", c2.View().Port, port)
	}
}

// TestRestoreWaitsForVPN covers the "重启时 VPN 未连接 → 等待，就绪后恢复" rule.
func TestRestoreWaitsForVPN(t *testing.T) {
	p, sink, nets, c, _ := setupShare(t)
	ctx := context.Background()
	if err := c.Enable(ctx, EnableOptions{PointID: "p1"}); err != nil {
		t.Fatal(err)
	}
	if err := c.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}

	// The VPN is not logged in yet when the app restarts.
	sink.setOffline(true)
	c2 := newTestController(t, p, sink, nets)
	if err := c2.Restore(ctx); err != nil {
		t.Fatalf("Restore while offline must not fail: %v", err)
	}
	waitState(t, c2, StateWaiting)
	if c2.View().Enabled != true {
		t.Fatal("a waiting share is still enabled")
	}
	if _, err := c2.ShareCode(); err == nil {
		t.Fatal("a waiting share must not print an unusable code")
	}
	if !strings.Contains(c2.View().Failure, "等待接入点连接") {
		t.Fatalf("waiting reason = %q", c2.View().Failure)
	}

	// The user's normal VPN login completes; the share resumes on its own.
	sink.setOffline(false)
	c2.Wake()
	waitState(t, c2, StateRunning)
	if _, err := c2.ShareCode(); err != nil {
		t.Fatalf("code should be available after resuming: %v", err)
	}
}

// TestDisableDoesNotRestore covers "主动关闭后不再恢复".
func TestDisableDoesNotRestore(t *testing.T) {
	p, sink, nets, c, _ := setupShare(t)
	ctx := context.Background()
	if err := c.Enable(ctx, EnableOptions{PointID: "p1"}); err != nil {
		t.Fatal(err)
	}
	codeBefore, _ := c.ShareCode()
	if err := c.Disable(ctx); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if c.View().State != StateOff {
		t.Fatalf("state = %s", c.View().State)
	}
	if p.ShareSettings().Enabled {
		t.Fatal("Disable must persist Enabled=false")
	}
	if p.secretCount() != 0 {
		t.Fatalf("Disable must drop the long-lived secrets, %d left", p.secretCount())
	}
	if _, err := c.ShareCode(); err == nil {
		t.Fatal("a disabled share still exposes a code")
	}

	// A restart must not bring it back.
	c2 := newTestController(t, p, sink, nets)
	if err := c2.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if c2.View().State != StateOff || c2.View().Enabled {
		t.Fatalf("disabled share restored: %+v", c2.View())
	}
	// Re-enabling mints a brand-new identity and token.
	if err := c2.Enable(ctx, EnableOptions{PointID: "p1"}); err != nil {
		t.Fatal(err)
	}
	codeAfter, err := c2.ShareCode()
	if err != nil {
		t.Fatal(err)
	}
	if codeAfter == codeBefore {
		t.Fatal("re-enabling must produce a new share code")
	}
}

// TestDisableClosesLiveClientAndRevokesToken is the "共享撤销后已有连接确实断开"
// requirement at the controller level.
func TestDisableClosesLiveClientAndRevokesToken(t *testing.T) {
	_, _, _, c, _ := setupShare(t)
	ctx := context.Background()
	if err := c.Enable(ctx, EnableOptions{PointID: "p1"}); err != nil {
		t.Fatal(err)
	}
	view := c.View()
	code := ShareCode{
		Version: 1, Host: "127.0.0.1", Port: view.Port,
		ShareID:     c.Settings().ShareID,
		Token:       shareTokenForTest(t, c),
		Fingerprint: c.Settings().Fingerprint,
	}
	client, err := NewClient(ClientOptions{Code: code})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	state, token, err := client.Open(ctx)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	conn, err := client.Dial(ctx, token, state.Epoch, state.Revision, "10.1.2.3:443")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	if err := c.Disable(ctx); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("existing tunnel survived 关闭共享")
	}
	if _, err := client.Status(ctx, token); err == nil {
		t.Fatal("client token still valid after 关闭共享")
	}
}

func shareTokenForTest(t *testing.T, c *Controller) string {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.token
}

// TestEnableRollbackOnPersistFailure: a first enable that cannot persist must
// leave nothing listening and no credentials behind.
func TestEnableRollbackOnPersistFailure(t *testing.T) {
	echo, closeEcho := echoServer(t)
	defer closeEcho()
	p := newFakePersistence()
	sink := newFakeSink("p1")
	sink.echo = echo
	nets := loopbackNets()
	c := newTestController(t, p, sink, nets)
	p.failSave = true
	err := c.Enable(context.Background(), EnableOptions{PointID: "p1"})
	if err == nil {
		t.Fatal("Enable must fail when the intent cannot be persisted")
	}
	if c.View().State != StateOff || c.View().Enabled {
		t.Fatalf("failed enable left a state behind: %+v", c.View())
	}
	if p.secretCount() != 0 {
		t.Fatalf("failed enable left %d secrets", p.secretCount())
	}
}

// TestEnableFirstBindConflictRollsBack: a port that is already taken is a hard
// first-enable failure, never a silent different port.
func TestEnableFirstBindConflictRollsBack(t *testing.T) {
	echo, closeEcho := echoServer(t)
	defer closeEcho()
	blocker, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	port := blocker.Addr().(*net.TCPAddr).Port

	p := newFakePersistence()
	sink := newFakeSink("p1")
	sink.echo = echo
	c := newTestController(t, p, sink, loopbackNets())
	err = c.Enable(context.Background(), EnableOptions{PointID: "p1", PreferredIPv4: "127.0.0.1", Port: port})
	if err == nil {
		t.Fatal("a taken port must fail the first enable")
	}
	if c.View().State != StateOff {
		t.Fatalf("state = %s, want off", c.View().State)
	}
	if p.ShareSettings().BoundPort != 0 {
		t.Fatalf("a failed enable persisted a bound port: %d", p.ShareSettings().BoundPort)
	}
}

// TestRestoreBindConflictIsBlocked: on restore the same conflict is a Blocked
// state that keeps the intent for a later retry.
func TestRestoreBindConflictIsBlocked(t *testing.T) {
	echo, closeEcho := echoServer(t)
	defer closeEcho()
	p := newFakePersistence()
	sink := newFakeSink("p1")
	sink.echo = echo
	nets := loopbackNets()
	c := newTestController(t, p, sink, nets)
	if err := c.Enable(context.Background(), EnableOptions{PointID: "p1"}); err != nil {
		t.Fatal(err)
	}
	port := c.View().Port
	if err := c.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	blocker, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = blocker.Close()
	// Occupy the exact port the share used.
	blocker, err = net.Listen("tcp4", net.JoinHostPort("127.0.0.1", itoa(port)))
	if err != nil {
		t.Skipf("cannot re-bind the previous port for the conflict test: %v", err)
	}
	defer blocker.Close()

	c2 := newTestController(t, p, sink, nets)
	_ = c2.Restore(context.Background())
	view := c2.View()
	if view.State != StateBlocked {
		t.Fatalf("state = %s, want blocked (view %+v)", view.State, view)
	}
	if !view.Enabled {
		t.Fatal("Blocked must keep the enable intent")
	}
	if view.Failure == "" {
		t.Fatal("Blocked must report a reason")
	}
}

// TestEnableRejectsUnknownPoint keeps an unshareable selection honest.
func TestEnableRejectsUnknownPoint(t *testing.T) {
	p := newFakePersistence()
	sink := newFakeSink("p1")
	c := newTestController(t, p, sink, loopbackNets())
	if err := c.Enable(context.Background(), EnableOptions{PointID: "missing"}); err == nil {
		t.Fatal("unknown point accepted")
	}
	if p.ShareSettings().Enabled {
		t.Fatal("a rejected enable must not persist intent")
	}
}

// TestSwitchPointRequiresDisable enforces "切换共享接入点必须关闭旧共享".
func TestSwitchPointRequiresDisable(t *testing.T) {
	_, _, _, c, _ := setupShare(t)
	ctx := context.Background()
	if err := c.Enable(ctx, EnableOptions{PointID: "p1"}); err != nil {
		t.Fatal(err)
	}
	if err := c.Enable(ctx, EnableOptions{PointID: "p2"}); err == nil {
		t.Fatal("switching the shared point without closing must fail")
	}
}

// TestDisablePersistFailureStillStops keeps the network honest: a failed save
// stops serving, reports the risk and suppresses restore for this run.
func TestDisablePersistFailureStillStops(t *testing.T) {
	p, sink, nets, c, _ := setupShare(t)
	ctx := context.Background()
	if err := c.Enable(ctx, EnableOptions{PointID: "p1"}); err != nil {
		t.Fatal(err)
	}
	p.failSave = true
	if err := c.Disable(ctx); err == nil {
		t.Fatal("a failed disable save must be reported")
	}
	if c.View().State != StateOff {
		t.Fatalf("state = %s, want off", c.View().State)
	}
	if !strings.Contains(c.View().Failure, "重启可能恢复") {
		t.Fatalf("failure text = %q", c.View().Failure)
	}
	// Even with the persisted value still true, this run must not restore.
	p.failSave = false
	c.Wake()
	time.Sleep(100 * time.Millisecond)
	if c.View().State == StateRunning {
		t.Fatal("a failed disable was silently restored in the same run")
	}
	_ = sink
	_ = nets
}

// TestAddressChangeIsBlocked: the identity is bound to one address; a changed
// address must ask the user instead of silently rebinding.
func TestAddressChangeIsBlocked(t *testing.T) {
	p, sink, nets, c, _ := setupShare(t)
	ctx := context.Background()
	if err := c.Enable(ctx, EnableOptions{PointID: "p1"}); err != nil {
		t.Fatal(err)
	}
	if err := c.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	nets.set(Interface{Name: "other", IPv4: "127.0.0.2"})
	c2 := newTestController(t, p, sink, nets)
	_ = c2.Restore(ctx)
	view := c2.View()
	if view.State != StateBlocked {
		t.Fatalf("state = %s, want blocked", view.State)
	}
	if !strings.Contains(view.Failure, "地址已变化") {
		t.Fatalf("failure = %q", view.Failure)
	}
}

// TestBlockedNeedsExplicitRetry: an automatic tick must not keep starting a share
// whose problem needs the user (a missing point, a taken port, a changed
// address). Only Waiting recovers by itself.
func TestBlockedNeedsExplicitRetry(t *testing.T) {
	p, sink, nets, c, _ := setupShare(t)
	ctx := context.Background()
	sink.setOffline(true)
	if err := c.Enable(ctx, EnableOptions{PointID: "p1"}); err != nil {
		t.Fatal(err)
	}
	waitState(t, c, StateWaiting)
	// The point disappears while the share waits.
	sink.setPoint("p1", "")
	sink.setOffline(false)
	c.Wake()
	waitState(t, c, StateBlocked)
	before := c.View().Operation
	// Give the 2s loop two chances: it must not touch a Blocked share.
	time.Sleep(2500 * time.Millisecond)
	after := c.View()
	if after.State != StateBlocked {
		t.Fatalf("a Blocked share restarted by itself: %+v", after)
	}
	if after.Operation != before {
		t.Fatalf("the reconcile loop advanced the operation of a Blocked share: %d → %d", before, after.Operation)
	}
	// Fixing the point plus an explicit retry works.
	sink.setPoint("p1", "接入点 p1")
	if err := c.Retry(ctx); err != nil {
		t.Fatal(err)
	}
	waitState(t, c, StateRunning)
	_ = nets
	_ = p
}

// TestEnableRollsBackWhenSecretsCannotBeStored: a share whose identity or token
// cannot be persisted must not start listening, must not keep the intent and must
// not leave partial secrets behind.
func TestEnableRollsBackWhenSecretsCannotBeStored(t *testing.T) {
	echo, closeEcho := echoServer(t)
	defer closeEcho()
	p := newFakePersistence()
	p.failSet = true
	sink := newFakeSink("p1")
	sink.echo = echo
	c := newTestController(t, p, sink, loopbackNets())
	err := c.Enable(context.Background(), EnableOptions{PointID: "p1"})
	if err == nil {
		t.Fatal("Enable must fail when the identity cannot be stored")
	}
	view := c.View()
	if view.State != StateOff || view.Enabled {
		t.Fatalf("failed enable left a state behind: %+v", view)
	}
	if _, err := c.ShareCode(); err == nil {
		t.Fatal("a failed enable exposed a share code")
	}
	if p.ShareSettings().Enabled {
		t.Fatal("a failed enable persisted Enabled=true")
	}
	// Nothing may be bound: a second Enable with a working store must be able to
	// use the same port without a conflict.
	p.failSet = false
	if err := c.Enable(context.Background(), EnableOptions{PointID: "p1"}); err != nil {
		t.Fatalf("retry after a failed enable: %v", err)
	}
	if c.View().State != StateRunning {
		t.Fatalf("retry did not start: %+v", c.View())
	}
}

// TestRetryPersistDisableCompletesTheClose: when the disabled state could not be
// written, the UI's retry must persist it and only then drop the recovery
// identity, so the next start stays off.
func TestRetryPersistDisableCompletesTheClose(t *testing.T) {
	p, sink, nets, c, _ := setupShare(t)
	ctx := context.Background()
	if err := c.Enable(ctx, EnableOptions{PointID: "p1"}); err != nil {
		t.Fatal(err)
	}
	p.failSave = true
	if err := c.Disable(ctx); err == nil {
		t.Fatal("a failed disable must be reported")
	}
	if c.View().FailureCode != "persist" {
		t.Fatalf("failure code = %q", c.View().FailureCode)
	}
	// The secrets must survive the failed save: the next start may still have to
	// resume, so they cannot be dropped yet.
	if p.secretCount() == 0 {
		t.Fatal("secrets were dropped before the disabled state was durable")
	}
	p.failSave = false
	if err := c.RetryPersistDisable(); err != nil {
		t.Fatalf("RetryPersistDisable: %v", err)
	}
	if p.ShareSettings().Enabled {
		t.Fatal("retry did not persist Enabled=false")
	}
	if p.secretCount() != 0 {
		t.Fatalf("retry left %d secrets", p.secretCount())
	}
	if c.View().FailureCode != "" {
		t.Fatalf("failure not cleared: %q", c.View().Failure)
	}
	c2 := newTestController(t, p, sink, nets)
	if err := c2.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if view := c2.View(); view.State != StateOff || view.Enabled {
		t.Fatalf("a completed close restored itself: %+v", view)
	}
}
