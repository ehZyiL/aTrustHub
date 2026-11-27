package process

import (
	"context"
	"io"
	"net"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/ehzyil/connect-hub/internal/relay"
	contract "github.com/ehzyil/connect-hub/internal/relay/contract"
	vpncontract "github.com/ehzyil/connect-hub/internal/vpn/contract"
	"github.com/ehzyil/connect-hub/internal/workeripc"
)

type testSource struct {
	mu       sync.RWMutex
	snapshot contract.SourceSnapshot
	changes  chan struct{}
	done     chan struct{}
	closed   sync.Once
	echo     string
}

func newTestSource(echo string) *testSource {
	resources := &contract.ResourceSnapshot{IPRules: []contract.IPRule{{
		Min: "10.1.0.0", Max: "10.1.255.255", PortMin: 443, PortMax: 443, Protocol: "tcp",
	}}}
	caps := contract.Capabilities{StrictTCP: true, InternalDNS: true}
	resources.Normalize()
	return &testSource{
		snapshot: contract.SourceSnapshot{Epoch: 1, Revision: resources.Revision(caps), Resources: resources, Capabilities: caps},
		changes:  make(chan struct{}, 1), done: make(chan struct{}), echo: echo,
	}
}

func (s *testSource) Snapshot(ctx context.Context) (contract.SourceSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return contract.SourceSnapshot{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snapshot, nil
}

func (s *testSource) DialVPN(ctx context.Context, revision, target string) (net.Conn, error) {
	s.mu.RLock()
	current := s.snapshot.Revision
	s.mu.RUnlock()
	if revision != current || target != "10.1.2.3:443" {
		return nil, relay.NewError(relay.CodeResourceDenied, "source refused target")
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", s.echo)
}

func (s *testSource) ExchangeDNS(ctx context.Context, revision string, query []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	current := s.snapshot.Revision
	s.mu.RUnlock()
	if revision != current || string(query) == "denied" {
		return nil, relay.NewError(relay.CodeResourceDenied, "DNS query refused")
	}
	return append([]byte("answer:"), query...), nil
}
func (s *testSource) Changes() <-chan struct{} { return s.changes }
func (s *testSource) Done() <-chan struct{}    { return s.done }
func (s *testSource) Close() error             { s.closed.Do(func() { close(s.done) }); return nil }

func (s *testSource) updateSnapshot() {
	s.mu.Lock()
	resources := s.snapshot.Resources.Clone()
	resources.DomainRules = append(resources.DomainRules, contract.DomainRule{Domain: "internal.test", PortMin: 443, PortMax: 443, Protocol: "tcp"})
	resources.Normalize()
	caps := s.snapshot.Capabilities
	s.snapshot = contract.SourceSnapshot{Epoch: s.snapshot.Epoch + 1, Revision: resources.Revision(caps), Resources: resources, Capabilities: caps}
	s.mu.Unlock()
	select {
	case s.changes <- struct{}{}:
	default:
	}
}

func buildRelayChild(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	name := "connect-hub-relay"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	out := filepath.Join(dir, name)
	root, err := filepath.Abs("../../../")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "build", "-mod=readonly", "-o", out, "./cmd/app-relay")
	cmd.Dir = root
	if data, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build relay child: %v\n%s", err, data)
	}
	return out
}

func TestRelaySidecarStrictStreamAndLifecycle(t *testing.T) {
	child := buildRelayChild(t)
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	source := newTestSource(echo.Addr().String())
	identity, err := relay.GenerateIdentity("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	server, err := Factory(child)(relay.ServerOptions{
		Identity: identity, Source: source, Token: "test-share-secret-with-enough-entropy",
		ShareID: "test-share", ServerInstanceID: "test-instance", Port: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close(context.Background()) })
	code := relay.ShareCode{Version: 1, Host: "127.0.0.1", Port: server.Port(), ShareID: "test-share",
		Token: "test-share-secret-with-enough-entropy", Fingerprint: identity.Fingerprint}
	client, err := relay.NewClient(relay.ClientOptions{Code: code, Dial: relay.DirectDialer})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	state, token, err := client.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := client.Dial(ctx, token, state.Epoch, state.Revision, "10.1.2.3:443")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "sidecar-data-path"); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("sidecar-data-path"))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if string(got) != "sidecar-data-path" {
		t.Fatalf("echo = %q", got)
	}
	if err := client.Revoke(ctx, token); err != nil {
		t.Fatal(err)
	}
	client.Close()
	if err := server.Close(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-server.(*processServer).done:
	case <-time.After(2 * time.Second):
		t.Fatal("relay process was not reaped")
	}
}

func TestFactoryDoesNotFallbackWhenComponentMissing(t *testing.T) {
	_, err := Factory("")(relay.ServerOptions{})
	if err == nil {
		t.Fatal("missing component unexpectedly started a server")
	}
}

func TestDiscoveryRuntimeStartsOnDemandAndStopsWhenIdle(t *testing.T) {
	child := buildRelayChild(t)
	runtime := NewDiscoveryRuntime(child, nil, nil, nil)
	if runtime.cmd != nil {
		t.Fatal("discovery process started before a task was requested")
	}
	pub, browser := runtime.Publisher(), runtime.Browser()
	if err := browser.Start(nil); err == nil {
		t.Fatal("empty interface selection unexpectedly started browsing")
	}
	if runtime.cmd == nil {
		t.Fatal("discovery task did not start the relay process")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runtime.mu.Lock()
	firstDone := runtime.procDone
	runtime.mu.Unlock()
	select {
	case <-firstDone:
	case <-ctx.Done():
		t.Fatal("idle discovery process did not stop")
	}
	if err := browser.Start(nil); err == nil {
		t.Fatal("discovery runtime did not restart for a new task")
	}
	if err := pub.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := browser.Shutdown(); err != nil {
		t.Fatal(err)
	}
	runtime.mu.Lock()
	done := runtime.procDone
	runtime.mu.Unlock()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("idle discovery process was not reaped")
	}
}

func TestImportedSessionSidecarUsesStrictBroker(t *testing.T) {
	child := buildRelayChild(t)
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	source := newTestSource(echo.Addr().String())
	identity, err := relay.GenerateIdentity("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	const shareToken = "test-share-secret-with-enough-entropy"
	host, err := relay.StartServer(relay.ServerOptions{Identity: identity, Source: source, Token: shareToken, ShareID: "import-share", ServerInstanceID: "host", Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Close(context.Background()); _ = source.Close() })
	point := model.AccessPoint{
		ID: "import-1", Name: "Imported", Protocol: model.ProtocolLANRelay, Server: "127.0.0.1", Port: host.Port(), InPool: true,
		Relay: &model.RelayPointOptions{Version: 1, ShareID: "import-share", CertificateSHA256: identity.Fingerprint},
	}
	var saved atomic.Int64
	connector := NewConnector(child, func(id string, got contract.RelaySnapshotSource, resources *workeripc.ResourceSnapshot) error {
		if id != point.ID || got.ShareID != point.Relay.ShareID || got.Fingerprint != identity.Fingerprint || resources == nil {
			t.Fatalf("invalid attribution: %q %+v %+v", id, got, resources)
		}
		saved.Add(1)
		return nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	session, err := connector(ctx, point, vpncontract.Credentials{Login: shareToken})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if saved.Load() != 1 || session.Info().Resources == nil {
		t.Fatalf("initial snapshot not committed: saves=%d info=%+v", saved.Load(), session.Info())
	}
	dnsAnswer, err := session.(vpncontract.DNSExchanger).ExchangeDNS(ctx, []byte("internal.test"))
	if err != nil || string(dnsAnswer) != "answer:internal.test" {
		t.Fatalf("internal DNS response = %q, err=%v", dnsAnswer, err)
	}
	if _, err := session.(vpncontract.DNSExchanger).ExchangeDNS(ctx, []byte("denied")); err == nil {
		t.Fatal("refused DNS query unexpectedly succeeded")
	}
	strict := session.(vpncontract.StrictSession)
	conn, err := strict.DialVPN(ctx, "tcp", "10.1.2.3:443")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "imported-sidecar"); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("imported-sidecar"))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if string(got) != "imported-sidecar" {
		t.Fatalf("echo = %q", got)
	}
	active, err := strict.DialVPN(ctx, "tcp", "10.1.2.3:443")
	if err != nil {
		t.Fatal(err)
	}
	imported := session.(*importedSession)
	imported.infoMu.RLock()
	oldRevision := imported.revision
	imported.infoMu.RUnlock()
	source.updateSnapshot()
	_ = active.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := active.Read(make([]byte, 1)); err == nil {
		t.Fatal("resource update left an old-version stream alive")
	}
	_ = active.Close()
	deadline := time.Now().Add(9 * time.Second)
	for time.Now().Before(deadline) {
		imported.infoMu.RLock()
		updated := imported.revision != oldRevision
		imported.infoMu.RUnlock()
		if updated {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	imported.infoMu.RLock()
	newRevision := imported.revision
	imported.infoMu.RUnlock()
	if newRevision == oldRevision || saved.Load() < 2 {
		t.Fatalf("resource version did not cross process boundary: %q -> %q, snapshots=%d", oldRevision, newRevision, saved.Load())
	}
	if _, err := imported.data.ExchangeDNS(ctx, oldRevision, []byte("internal.test")); err == nil {
		t.Fatal("stale resource version was accepted for DNS")
	}
	if _, err := imported.data.DialVPN(ctx, oldRevision, "10.1.2.3:443"); err == nil {
		t.Fatal("stale resource version was accepted by the import data channel")
	}
	updatedConn, err := strict.DialVPN(ctx, "tcp", "10.1.2.3:443")
	if err != nil {
		t.Fatalf("updated authorized target failed: %v", err)
	}
	_ = updatedConn.Close()
	if _, err := strict.DialVPN(ctx, "tcp", "203.0.113.8:443"); err == nil {
		t.Fatal("unowned target unexpectedly used the strict session")
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-session.(vpncontract.SessionWatcher).Done():
	case <-time.After(2 * time.Second):
		t.Fatal("import relay process was not reaped")
	}
}
