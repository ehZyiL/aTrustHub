package store_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/ehzyil/connect-hub/internal/relay"
	"github.com/ehzyil/connect-hub/internal/store"
)

// integrationSource is a minimal relay.Source: one authorized range, dialing a
// local echo listener so a tunnel can be proven.
type integrationSource struct {
	mu     sync.Mutex
	snap   relay.SourceSnapshot
	done   chan struct{}
	closed sync.Once
	echo   string
}

func newIntegrationSource(echo string) *integrationSource {
	res := &relay.ResourceSnapshot{
		IPRules: []relay.IPRule{{Min: "10.5.0.0", Max: "10.5.255.255", PortMin: 443, PortMax: 443, Protocol: "tcp"}},
	}
	res.Normalize()
	caps := relay.Capabilities{StrictTCP: true}
	return &integrationSource{
		snap: relay.SourceSnapshot{Epoch: 1, Revision: res.Revision(caps), Resources: res, Capabilities: caps},
		done: make(chan struct{}),
		echo: echo,
	}
}

func (s *integrationSource) Snapshot(context.Context) (relay.SourceSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snap, nil
}

func (s *integrationSource) DialVPN(ctx context.Context, revision, target string) (net.Conn, error) {
	return net.Dial("tcp", s.echo)
}

func (s *integrationSource) ExchangeDNS(context.Context, string, []byte) ([]byte, error) {
	return nil, relay.NewError(relay.CodeProtocolUnsupported, "not supported")
}

func (s *integrationSource) Changes() <-chan struct{} { return make(chan struct{}) }
func (s *integrationSource) Done() <-chan struct{}    { return s.done }
func (s *integrationSource) Close() error {
	s.closed.Do(func() { close(s.done) })
	return nil
}

type integrationSink struct {
	mu    sync.Mutex
	names map[string]string
	echo  string
}

func (s *integrationSink) AcquireSource(ctx context.Context, id string) (relay.Source, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.names[id]; !ok {
		return nil, relay.ErrPointMissing
	}
	return newIntegrationSource(s.echo), nil
}

func (s *integrationSink) PointName(id string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.names[id]
}

func (s *integrationSink) PointExists(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.names[id]
	return ok
}

type loopbackNet struct{}

func (loopbackNet) LANCandidates() []relay.Interface {
	return []relay.Interface{{Name: "lo-test", IPv4: "127.0.0.1"}}
}

func echoListener(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						_, _ = c.Write(buf[:n])
					}
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

// TestLANShareSurvivesRestartThroughRealStore is the end-to-end persistence
// check: enable → restart → restored with the same identity/address/port →
// disable → restart stays off, with the real Store adapter and a real listener.
func TestLANShareSurvivesRestartThroughRealStore(t *testing.T) {
	dir := t.TempDir()
	secrets := store.NewMemorySecrets()
	st, err := store.Open(dir, secrets)
	if err != nil {
		t.Fatal(err)
	}
	point := model.AccessPoint{
		ID: "a1", Name: "公司 VPN", Protocol: model.ProtocolATrust,
		Server: "vpn.example.com", Port: 443, Username: "u", InPool: true,
	}
	if _, err := st.Update(func(cfg *model.Config) error {
		cfg.Add(point)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	echo, closeEcho := echoListener(t)
	defer closeEcho()
	sink := &integrationSink{names: map[string]string{"a1": "公司 VPN"}, echo: echo}

	ctrl := relay.NewController(store.RelayShareStore{Store: st}, sink, loopbackNet{}, nil, nil)
	ctx := context.Background()
	if err := ctrl.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	if view := ctrl.View(); view.State != relay.StateOff || view.Enabled {
		t.Fatalf("a fresh install must start off: %+v", view)
	}
	if err := ctrl.Enable(ctx, relay.EnableOptions{PointID: "a1"}); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	view := ctrl.View()
	if view.State != relay.StateRunning {
		t.Fatalf("state = %s", view.State)
	}
	codeBefore, err := ctrl.ShareCode()
	if err != nil {
		t.Fatal(err)
	}
	portBefore := view.Port
	shareID := ctrl.Settings().ShareID

	// The intent is in config.json; the secrets are in the credential store.
	adapter := store.RelayShareStore{Store: st}
	persisted := adapter.ShareSettings()
	if !persisted.Enabled || persisted.BoundPort != portBefore || persisted.ShareID != shareID {
		t.Fatalf("persisted settings wrong: %+v", persisted)
	}
	if _, err := adapter.GetSecret(relay.ShareTokenKey(shareID)); err != nil {
		t.Fatalf("share token not in the credential store: %v", err)
	}

	if err := ctrl.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}

	// Restart: reopen the store from disk and restore.
	st2, err := store.Open(dir, secrets)
	if err != nil {
		t.Fatal(err)
	}
	persisted2 := store.RelayShareStore{Store: st2}.ShareSettings()
	if !persisted2.Enabled {
		t.Fatal("Enabled did not survive the restart")
	}
	ctrl2 := relay.NewController(store.RelayShareStore{Store: st2}, sink, loopbackNet{}, nil, nil)
	if err := ctrl2.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for ctrl2.View().State != relay.StateRunning && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if ctrl2.View().State != relay.StateRunning {
		t.Fatalf("restore did not reach running: %+v", ctrl2.View())
	}
	codeAfter, err := ctrl2.ShareCode()
	if err != nil {
		t.Fatal(err)
	}
	if codeAfter != codeBefore {
		t.Fatalf("share code changed across a restart:\n%s\n%s", codeBefore, codeAfter)
	}

	// A client tunnel really works against the restored instance.
	parsed, err := relay.ParseShareCode(codeAfter)
	if err != nil {
		// The identity is bound to loopback in this test, which the strict
		// parser refuses by design; build the equivalent struct instead.
		parsed = relay.ShareCode{
			Version: 1, Host: "127.0.0.1", Port: ctrl2.View().Port,
			ShareID: ctrl2.Settings().ShareID, Token: tokenOf(t, st2, ctrl2.Settings().ShareID),
			Fingerprint: ctrl2.Settings().Fingerprint,
		}
	}
	client, err := relay.NewClient(relay.ClientOptions{Code: parsed})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	state, token, err := client.Open(ctx)
	if err != nil {
		t.Fatalf("client Open: %v", err)
	}
	conn, err := client.Dial(ctx, token, state.Epoch, state.Revision, "10.5.1.2:443")
	if err != nil {
		t.Fatalf("tunnel: %v", err)
	}
	_ = conn.Close()

	// 关闭共享 must revoke and must not come back.
	if err := ctrl2.Disable(ctx); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	adapter2 := store.RelayShareStore{Store: st2}
	if adapter2.ShareSettings().Enabled {
		t.Fatal("Disable did not persist Enabled=false")
	}
	if _, err := adapter2.GetSecret(relay.ShareTokenKey(shareID)); err == nil {
		t.Fatal("the share token survived a deliberate disable")
	}
	st3, err := store.Open(dir, secrets)
	if err != nil {
		t.Fatal(err)
	}
	ctrl3 := relay.NewController(store.RelayShareStore{Store: st3}, sink, loopbackNet{}, nil, nil)
	if err := ctrl3.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	if view := ctrl3.View(); view.State != relay.StateOff || view.Enabled {
		t.Fatalf("a disabled share came back after restart: %+v", view)
	}
	if _, err := ctrl3.ShareCode(); err == nil {
		t.Fatal("a disabled share still exposes a code")
	}
	_ = ctrl3.Shutdown(ctx)
}

func tokenOf(t *testing.T, st *store.Store, shareID string) string {
	t.Helper()
	token, err := store.RelayShareStore{Store: st}.GetSecret(relay.ShareTokenKey(shareID))
	if err != nil {
		t.Fatalf("share token missing: %v", err)
	}
	return token
}

// TestLANShareRestoreWaitsWithoutVPNThroughRealStore keeps the "waiting" path
// honest with the production adapter too.
func TestLANShareRestoreWaitsWithoutVPNThroughRealStore(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir, store.NewMemorySecrets())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Update(func(cfg *model.Config) error {
		cfg.Add(model.AccessPoint{ID: "a1", Name: "公司 VPN", Protocol: model.ProtocolATrust, Server: "vpn.example.com", Port: 443, Username: "u", InPool: true})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	echo, closeEcho := echoListener(t)
	defer closeEcho()
	sink := &integrationSink{names: map[string]string{"a1": "公司 VPN"}, echo: echo}
	offlineSink := &offlineIntegrationSink{integrationSink: sink}

	ctrl := relay.NewController(store.RelayShareStore{Store: st}, sink, loopbackNet{}, nil, nil)
	ctx := context.Background()
	if err := ctrl.Enable(ctx, relay.EnableOptions{PointID: "a1"}); err != nil {
		t.Fatal(err)
	}
	if err := ctrl.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}

	offlineSink.offline = true
	ctrl2 := relay.NewController(store.RelayShareStore{Store: st}, offlineSink, loopbackNet{}, nil, nil)
	if err := ctrl2.Restore(ctx); err != nil {
		t.Fatalf("offline restore must not fail: %v", err)
	}
	view := ctrl2.View()
	if view.State != relay.StateWaiting {
		t.Fatalf("state = %s, want waiting", view.State)
	}
	if !view.Enabled {
		t.Fatal("waiting share lost its enable intent")
	}
	if _, err := ctrl2.ShareCode(); err == nil {
		t.Fatal("waiting share exposed a code")
	}
	offlineSink.offline = false
	ctrl2.Wake()
	deadline := time.Now().Add(5 * time.Second)
	for ctrl2.View().State != relay.StateRunning && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if ctrl2.View().State != relay.StateRunning {
		t.Fatalf("share did not resume once the VPN was ready: %+v", ctrl2.View())
	}
	_ = ctrl2.Shutdown(ctx)
}

type offlineIntegrationSink struct {
	*integrationSink
	offline bool
}

func (s *offlineIntegrationSink) AcquireSource(ctx context.Context, id string) (relay.Source, error) {
	if s.offline {
		return nil, relay.ErrPointNotReady
	}
	return s.integrationSink.AcquireSource(ctx, id)
}
