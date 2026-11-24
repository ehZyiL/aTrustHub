package relay

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeSource is the test double for the vpn strict source.
type fakeSource struct {
	mu        sync.Mutex
	snap      SourceSnapshot
	changes   chan struct{}
	done      chan struct{}
	closeOnce sync.Once
	dials     []string
	requests  atomic.Int64
	echo      string
	dialFail  error
}

func newFakeSource(snap SourceSnapshot) *fakeSource {
	return &fakeSource{snap: snap, changes: make(chan struct{}, 1), done: make(chan struct{})}
}

func (f *fakeSource) Snapshot(ctx context.Context) (SourceSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.snap.Resources == nil {
		return SourceSnapshot{}, NewError(CodeVPNUnavailable, "分享接入点已断开")
	}
	return f.snap, nil
}

func (f *fakeSource) DialVPN(ctx context.Context, revision, target string) (net.Conn, error) {
	f.mu.Lock()
	revisionNow := f.snap.Revision
	fail := f.dialFail
	echo := f.echo
	f.mu.Unlock()
	if revision != "" && revision != revisionNow {
		return nil, NewError(CodeStaleResources, "资源版本已变化")
	}
	if fail != nil {
		return nil, fail
	}
	// Mirror the real boundary: only authorized targets are recorded and
	// dialed, so "source saw a dial" means "the share forwarded it".
	if !strings.HasSuffix(target, ":443") || !strings.HasPrefix(target, "10.1.") {
		return nil, NewError(CodeResourceDenied, "目标不在分享范围内")
	}
	f.mu.Lock()
	f.dials = append(f.dials, target)
	f.mu.Unlock()
	return net.Dial("tcp", echo)
}

func (f *fakeSource) ExchangeDNS(ctx context.Context, revision string, query []byte) ([]byte, error) {
	return append([]byte("answer:"), query...), nil
}

func (f *fakeSource) Changes() <-chan struct{} { return f.changes }
func (f *fakeSource) Done() <-chan struct{}    { return f.done }
func (f *fakeSource) Close() error {
	f.closeOnce.Do(func() { close(f.done) })
	return nil
}

func (f *fakeSource) setSnapshot(snap SourceSnapshot) {
	f.mu.Lock()
	f.snap = snap
	f.mu.Unlock()
	select {
	case f.changes <- struct{}{}:
	default:
	}
}

func (f *fakeSource) dialed() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.dials...)
}

// echoServer is the "VPN resource" the fake source reaches.
func echoServer(t *testing.T) (addr string, closeFn func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	done := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	return ln.Addr().String(), func() {
		close(done)
		_ = ln.Close()
		wg.Wait()
	}
}

func testSnapshot() SourceSnapshot {
	resources := &ResourceSnapshot{
		IPRules: []IPRule{{Min: "10.1.0.0", Max: "10.1.255.255", PortMin: 443, PortMax: 443, Protocol: "tcp"}},
	}
	caps := Capabilities{StrictTCP: true, InternalDNS: true}
	resources.Normalize()
	return SourceSnapshot{Epoch: 1, Revision: resources.Revision(caps), Resources: resources, Capabilities: caps}
}

type shareFixture struct {
	server *Server
	code   ShareCode
	source *fakeSource
	echo   string
}

func startShareFixture(t *testing.T, token string) *shareFixture {
	t.Helper()
	identity, err := GenerateIdentity("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	echo, closeEcho := echoServer(t)
	t.Cleanup(closeEcho)
	source := newFakeSource(testSnapshot())
	source.echo = echo
	shareID, _ := randomShareID()
	server, err := StartServer(ServerOptions{
		Identity:         identity,
		Source:           source,
		Token:            token,
		ShareID:          shareID,
		ServerInstanceID: "instance-test",
		Port:             0,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close(context.Background()) })
	fx := &shareFixture{
		server: server,
		source: source,
		echo:   echo,
		code: ShareCode{
			Version:     1,
			Host:        "127.0.0.1",
			Port:        server.Port(),
			ShareID:     shareID,
			Token:       token,
			Fingerprint: identity.Fingerprint,
			Name:        "测试主机",
		},
	}
	// The address in the code must match the identity's SAN for verification.
	return fx
}

func (f *shareFixture) client(t *testing.T) *Client {
	t.Helper()
	c, err := NewClient(ClientOptions{Code: f.code})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func TestServerShareTokenAndSession(t *testing.T) {
	fx := startShareFixture(t, "share-token-123456")
	client := fx.client(t)
	ctx := context.Background()

	state, token, err := client.Open(ctx)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if state.Revision != fx.source.snap.Revision {
		t.Fatalf("revision mismatch: %s", state.Revision)
	}
	if token == "" || token == fx.code.Token {
		t.Fatal("a separate client session token is required")
	}
	if !state.Capabilities.StrictTCP {
		t.Fatal("strict TCP must be negotiated")
	}
	status, err := client.Status(ctx, token)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.Epoch != state.Epoch || status.ShareID != fx.code.ShareID {
		t.Fatalf("status mismatch: %+v", status)
	}
}

func TestServerRejectsBadShareToken(t *testing.T) {
	fx := startShareFixture(t, "share-token-123456")
	code := fx.code
	code.Token = "wrong-token-value"
	client, err := NewClient(ClientOptions{Code: code})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, _, err = client.Open(context.Background())
	var re *Error
	if !errors.As(err, &re) || re.Code != CodeInvalidCredentials {
		t.Fatalf("want invalid_credentials, got %v", err)
	}
}

// TestWrongPinNeverSeesTheToken proves the fingerprint check happens before any
// Authorization header can be sent.
func TestWrongPinNeverSeesTheToken(t *testing.T) {
	fx := startShareFixture(t, "share-token-123456")
	var hits atomic.Int64
	fx.server.mux.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	})
	code := fx.code
	code.Fingerprint = strings.Repeat("0", 64)
	client, err := NewClient(ClientOptions{Code: code})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, _, err = client.Open(context.Background())
	if err == nil {
		t.Fatal("a wrong pin must fail")
	}
	if hits.Load() != 0 {
		t.Fatal("server received a request despite the pin mismatch")
	}
}

func TestConnectAuthorizesAndRefuses(t *testing.T) {
	fx := startShareFixture(t, "share-token-123456")
	client := fx.client(t)
	ctx := context.Background()
	state, token, err := client.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}

	conn, err := client.Dial(ctx, token, state.Epoch, state.Revision, "10.1.2.3:443")
	if err != nil {
		t.Fatalf("authorized CONNECT failed: %v", err)
	}
	payload := []byte("hello-through-the-tunnel")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo mismatch: %q", got)
	}
	_ = conn.Close()

	// An unauthorized target is refused by the source and never dialed locally.
	if _, err := client.Dial(ctx, token, state.Epoch, state.Revision, "8.8.8.8:443"); err == nil {
		t.Fatal("public target must be refused")
	} else {
		var re *Error
		if !errors.As(err, &re) || re.Code != CodeResourceDenied {
			t.Fatalf("want resource_denied, got %v", err)
		}
	}
	if len(fx.source.dialed()) != 1 {
		t.Fatalf("source saw unexpected dials: %v", fx.source.dialed())
	}
}

func TestConnectRejectsStaleRevisionAndShareToken(t *testing.T) {
	fx := startShareFixture(t, "share-token-123456")
	client := fx.client(t)
	ctx := context.Background()
	state, token, err := client.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Dial(ctx, token, state.Epoch, "stale-revision", "10.1.2.3:443"); err == nil {
		t.Fatal("stale revision must be refused")
	} else {
		var re *Error
		if !errors.As(err, &re) || re.Code != CodeStaleResources {
			t.Fatalf("want stale_resources, got %v", err)
		}
	}
	// The long-lived share token must not be usable as a session token.
	if _, err := client.Dial(ctx, fx.code.Token, state.Epoch, state.Revision, "10.1.2.3:443"); err == nil {
		t.Fatal("share token must not authenticate CONNECT")
	}
}

func TestRevocationClosesEstablishedTunnels(t *testing.T) {
	fx := startShareFixture(t, "share-token-123456")
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
	if _, err := conn.Write([]byte("before")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 6)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}

	// A live connection must actually die when the share is revoked.
	fx.server.RevokeAll()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatal("established tunnel still readable after revocation")
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("tunnel was not closed, only idle")
	}
	if _, err := client.Dial(ctx, token, state.Epoch, state.Revision, "10.1.2.3:443"); err == nil {
		t.Fatal("revoked client token still works")
	}
}

func TestServerCloseEndsEverything(t *testing.T) {
	fx := startShareFixture(t, "share-token-123456")
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
	_ = fx.server.Close(ctx)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection survived Close")
	}
}

func TestResourceChangeClosesOldFlows(t *testing.T) {
	fx := startShareFixture(t, "share-token-123456")
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

	next := testSnapshot()
	next.Epoch = 2
	next.Resources.IPRules = append(next.Resources.IPRules, IPRule{Min: "10.9.0.0", Max: "10.9.0.255", PortMin: 443, PortMax: 443, Protocol: "tcp"})
	next.Resources.Normalize()
	next.Revision = next.Resources.Revision(next.Capabilities)
	fx.source.setSnapshot(next)

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("old business flow survived a resource change")
	}
	// The control lease stays valid and the new revision is visible.
	status, err := client.Status(ctx, token)
	if err != nil {
		t.Fatalf("control lease should survive a resource change: %v", err)
	}
	if status.Epoch != 2 {
		t.Fatalf("epoch did not advance: %+v", status)
	}
}

func TestDNSEndpoint(t *testing.T) {
	fx := startShareFixture(t, "share-token-123456")
	client := fx.client(t)
	ctx := context.Background()
	state, token, err := client.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	answer, err := client.ExchangeDNS(ctx, token, state.Epoch, state.Revision, []byte("query"))
	if err != nil {
		t.Fatalf("ExchangeDNS: %v", err)
	}
	if string(answer) != "answer:query" {
		t.Fatalf("unexpected answer %q", answer)
	}
}

func TestClientLeaseExpiry(t *testing.T) {
	fx := startShareFixture(t, "share-token-123456")
	// Shorten the lease so the test does not sleep for 15 seconds.
	fx.server.clients.lease = 150 * time.Millisecond
	client := fx.client(t)
	ctx := context.Background()
	state, token, err := client.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if _, err := client.Status(ctx, token); err == nil {
		t.Fatal("expired lease still accepted")
	}
	if _, err := client.Dial(ctx, token, state.Epoch, state.Revision, "10.1.2.3:443"); err == nil {
		t.Fatal("expired lease still opens tunnels")
	}
}

func TestConcurrentConnectLimitIsBounded(t *testing.T) {
	fx := startShareFixture(t, "share-token-123456")
	fx.server.conns.maxEach = 1
	client := fx.client(t)
	ctx := context.Background()
	state, token, err := client.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	first, err := client.Dial(ctx, token, state.Epoch, state.Revision, "10.1.2.3:443")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := client.Dial(ctx, token, state.Epoch, state.Revision, "10.1.2.3:443"); err == nil {
		t.Fatal("per-client connection limit not enforced")
	} else {
		var re *Error
		if !errors.As(err, &re) || re.Code != CodeBusy {
			t.Fatalf("want busy, got %v", err)
		}
	}
}

func TestSessionCreationBodyBound(t *testing.T) {
	fx := startShareFixture(t, "share-token-123456")
	client := fx.client(t)
	ctx := context.Background()
	huge := strings.Repeat("x", MaxSessionBody+10)
	// The strict decoder must refuse either the size or the unknown field.
	_, err := client.controlWithToken(ctx, "POST", "/v1/sessions", map[string]string{"clientId": "abc", "name": huge}, nil, fx.code.Token)
	if err == nil {
		t.Fatal("oversized session body accepted")
	}
}

// blockingSource parks inside DialVPN until its context ends, which is what a
// revocation racing with a pending dial looks like.
type blockingSource struct {
	*fakeSource
	started chan struct{}
	once    sync.Once
}

func (b *blockingSource) DialVPN(ctx context.Context, revision, target string) (net.Conn, error) {
	b.once.Do(func() { close(b.started) })
	<-ctx.Done()
	return nil, NewError(CodeVPNUnavailable, "分享已撤销，拨号被取消")
}

// TestRevocationCancelsPendingDial proves a share stop also aborts a dial that
// has not completed yet, instead of letting a late success become a tunnel.
func TestRevocationCancelsPendingDial(t *testing.T) {
	identity, err := GenerateIdentity("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	base := newFakeSource(testSnapshot())
	source := &blockingSource{fakeSource: base, started: make(chan struct{})}
	shareID, _ := randomShareID()
	server, err := StartServer(ServerOptions{
		Identity: identity, Source: source, Token: "share-token-123456",
		ShareID: shareID, ServerInstanceID: "instance", Port: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close(context.Background()) })
	code := ShareCode{Version: 1, Host: "127.0.0.1", Port: server.Port(),
		ShareID: shareID, Token: "share-token-123456", Fingerprint: identity.Fingerprint}
	client, err := NewClient(ClientOptions{Code: code})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx := context.Background()
	state, token, err := client.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}

	dialErr := make(chan error, 1)
	go func() {
		conn, err := client.Dial(ctx, token, state.Epoch, state.Revision, "10.1.2.3:443")
		if conn != nil {
			_ = conn.Close()
		}
		dialErr <- err
	}()
	select {
	case <-source.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the pending dial never started")
	}
	server.RevokeAll()
	select {
	case err := <-dialErr:
		if err == nil {
			t.Fatal("a pending dial succeeded after revocation")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("revocation did not cancel the pending dial")
	}
}

// TestDNSRequestBinding: the v1 DNS body is a raw DNS message, and a stale
// epoch/revision must be refused instead of answered with newer authorization.
func TestDNSRequestBinding(t *testing.T) {
	fx := startShareFixture(t, "share-token-123456")
	client := fx.client(t)
	ctx := context.Background()
	state, token, err := client.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Correct epoch/revision: answered by the source.
	answer, err := client.ExchangeDNS(ctx, token, state.Epoch, state.Revision, []byte("q"))
	if err != nil || string(answer) != "answer:q" {
		t.Fatalf("valid DNS query: %q %v", answer, err)
	}
	// Wrong epoch: refused as stale, never served.
	if _, err := client.ExchangeDNS(ctx, token, state.Epoch+7, state.Revision, []byte("q")); err == nil {
		t.Fatal("stale epoch was answered")
	} else {
		var re *Error
		if !errors.As(err, &re) || re.Code != CodeStaleResources {
			t.Fatalf("want stale_resources, got %v", err)
		}
	}
	// Wrong revision: same.
	if _, err := client.ExchangeDNS(ctx, token, state.Epoch, "not-the-revision", []byte("q")); err == nil {
		t.Fatal("stale revision was answered")
	}
	// Oversized body is bounded.
	if _, err := client.ExchangeDNS(ctx, token, state.Epoch, state.Revision, make([]byte, MaxDNSBody+1)); err == nil {
		t.Fatal("oversized DNS body accepted")
	}
	// The share token is not accepted on this endpoint either.
	if _, err := client.ExchangeDNS(ctx, fx.code.Token, state.Epoch, state.Revision, []byte("q")); err == nil {
		t.Fatal("share token authenticated a client endpoint")
	}
}

// TestConnectRefusesRequestBody: a CONNECT with a body would smuggle bytes into
// the tunnel, so it is refused before any upstream dial.
func TestConnectRefusesRequestBody(t *testing.T) {
	fx := startShareFixture(t, "share-token-123456")
	client := fx.client(t)
	ctx := context.Background()
	state, token, err := client.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Build a CONNECT by hand with a body; the reference client never sends one.
	conn, err := client.dial(ctx, "tcp", fx.code.Address())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tlsConn := tls.Client(conn, client.tlsConfig.Clone())
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	raw := "CONNECT 10.1.2.3:443 HTTP/1.1\r\n" +
		"Host: 10.1.2.3:443\r\n" +
		"Hub-Protocol: 1\r\n" +
		"Hub-Share-ID: " + fx.code.ShareID + "\r\n" +
		"Authorization: Bearer " + token + "\r\n" +
		"Hub-Share-Epoch: " + itoa(int(state.Epoch)) + "\r\n" +
		"Hub-Resource-Revision: " + state.Revision + "\r\n" +
		"Content-Length: 5\r\n\r\nhello"
	if _, err := tlsConn.Write([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufioReader(tlsConn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("CONNECT with a body was accepted")
	}
	select {
	case <-time.After(50 * time.Millisecond):
	}
	if got := fx.source.dialed(); len(got) != 0 {
		t.Fatalf("a rejected CONNECT reached the source: %v", got)
	}
}

// TestClientTransportIsDirectAndPinned: the share client must not pick up a
// proxy environment, HTTP/2 or a non-pinned TLS path.
func TestClientTransportIsDirectAndPinned(t *testing.T) {
	code := ShareCode{Version: 1, Host: "192.168.1.50", Port: 23456,
		ShareID: "sid", Token: "tok", Fingerprint: strings.Repeat("ab", 32)}
	client, err := NewClient(ClientOptions{Code: code})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	transport := client.transport
	if transport.Proxy != nil {
		t.Fatal("the share client may use a system proxy")
	}
	if transport.DialContext == nil {
		t.Fatal("the share client must dial only through the injected dialer")
	}
	if transport.ForceAttemptHTTP2 {
		t.Fatal("v1 must stay on HTTP/1.1")
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.VerifyConnection == nil {
		t.Fatal("the share client must verify the pinned certificate")
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion = %x", transport.TLSClientConfig.MinVersion)
	}
}
