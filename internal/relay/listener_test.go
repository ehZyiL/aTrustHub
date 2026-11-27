package relay

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

// All probes use this test's loopback listener, never a running share.
func TestUnauthenticatedSocketsCannotBlockPairedReconnect(t *testing.T) {
	s, target, invite, _ := pairFixture(t)
	_, c, token := approvePair(t, s, target, invite.PIN)
	_, other, otherToken := approvePair(t, s, target, invite.PIN)
	status, err := c.Status(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	old, err := c.Dial(context.Background(), token, status.Epoch, status.Revision, "10.1.2.3:443")
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	otherState, err := other.Status(context.Background(), otherToken)
	if err != nil {
		t.Fatal(err)
	}
	otherTunnel, err := other.Dial(context.Background(), otherToken, otherState.Epoch, otherState.Revision, "10.1.2.3:443")
	if err != nil {
		t.Fatal(err)
	}
	defer otherTunnel.Close()
	var raw []net.Conn
	defer func() {
		for _, conn := range raw {
			conn.Close()
		}
	}()
	for range MaxUnauthenticated + MaxBusinessConnsTotal + 2 {
		conn, err := net.DialTimeout("tcp", s.ListenAddress(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, conn)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	expectOpen(t, old)
	expectOpen(t, otherTunnel)
	if _, err := other.Status(ctx, otherToken); err != nil {
		t.Fatal("other device control stopped", err)
	}
	// A fresh v2 proof and fresh control/tunnel must pass even if the old
	// control transport has been discarded.
	c.Close()
	code := c.code
	fresh, err := NewClient(ClientOptions{Code: code})
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	state, nextToken, err := fresh.Open(ctx)
	if err != nil {
		t.Fatalf("paired reconnect behind unauthenticated sockets: %v", err)
	}
	conn, err := fresh.Dial(ctx, nextToken, state.Epoch, state.Revision, "10.1.2.3:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	expectOpen(t, conn)
	expectOpen(t, otherTunnel)
	if _, err := other.Status(ctx, otherToken); err != nil {
		t.Fatal(err)
	}
	if _, err := other.ExchangeDNS(ctx, otherToken, otherState.Epoch, otherState.Revision, []byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	legacy, err := NewClient(ClientOptions{Code: ShareCode{Version: 1, Host: target.Host, Port: s.Port(), ShareID: s.shareID, Token: s.token, Fingerprint: s.identity.Fingerprint}})
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.Close()
	if _, _, err := legacy.Open(ctx); err != nil {
		t.Fatal("v1 admission blocked", err)
	}
}

func listenerCounts(l *limitedListener) [4]int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.used
}

func TestUnauthenticatedHTTPKeepAliveIsClosed(t *testing.T) {
	fx := startShareFixture(t, "listener-http")
	cfg, _ := ClientTLSConfig(fx.code.Fingerprint, fx.code.Host)
	l := fx.server.ln.(*limitedListener)
	// Explicit keep-alive requests must not park one slot per 404 response.
	for range MaxUnauthenticated + 2 {
		conn, err := tls.Dial("tcp", fx.server.ListenAddress(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		req, _ := http.NewRequest(http.MethodGet, "https://"+fx.server.ListenAddress()+"/missing", nil)
		if err := req.Write(conn); err != nil {
			t.Fatal(err)
		}
		reader := bufio.NewReader(conn)
		resp, err := http.ReadResponse(reader, req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusNotFound || !resp.Close {
			t.Fatal("unauthenticated response kept connection alive")
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if _, err := reader.ReadByte(); err == nil {
			t.Fatal("404 socket remained open")
		}
	}
	waitRelay(t, "404 sockets release their budget", func() bool { return listenerCounts(l)[0] == 0 })
}

func TestListenerAuthenticationMigrationAndBounds(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := newLimitedListener(ln, 2)
	l.limits[connectionControl] = 1
	defer l.Close()
	accept := func() *limitedConn {
		peer, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { peer.Close() })
		conn, err := l.Accept()
		if err != nil {
			t.Fatal(err)
		}
		return conn.(*limitedConn)
	}
	control := accept()
	if err := control.promote(connectionControl); err != nil {
		t.Fatal(err)
	}
	first, second := accept(), accept()
	third := accept() // oldest unauthenticated is reclaimed, control survives
	if got := listenerCounts(l); got != [4]int{2, 1, 0, 0} {
		t.Fatal(got)
	}
	if err := first.promote(connectionTunnel); !errors.Is(err, net.ErrClosed) {
		t.Fatal("reclaimed socket promoted", err)
	}
	if err := second.promote(connectionControl); err == nil {
		t.Fatal("control limit bypassed")
	}
	if err := third.promote(connectionTunnel); err != nil {
		t.Fatal(err)
	}
	if err := second.promote(connectionPair); err != nil {
		t.Fatal(err)
	}
	if got := listenerCounts(l); got != [4]int{0, 1, 1, 1} {
		t.Fatal(got)
	}
	// Repeated promotion/closure cannot return the same permit twice.
	if err := third.promote(connectionTunnel); err != nil {
		t.Fatal(err)
	}
	first.Close()
	first.Close()
	third.Close()
	third.Close()
	if got := listenerCounts(l); got != [4]int{0, 1, 0, 1} {
		t.Fatal(got)
	}
	l.Close()
	if got := listenerCounts(l); got != [4]int{} {
		t.Fatal("leaked permits", got)
	}
}

func TestListenerPromotionRacesCloseWithoutLeaking(t *testing.T) {
	for range 50 {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		l := newLimitedListener(ln, 1)
		peer, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		conn, err := l.Accept()
		if err != nil {
			t.Fatal(err)
		}
		c := conn.(*limitedConn)
		var wg sync.WaitGroup
		wg.Add(4)
		go func() { defer wg.Done(); _ = c.promote(connectionControl) }()
		go func() { defer wg.Done(); c.closeUnauthenticated() }()
		go func() { defer wg.Done(); _ = c.Close() }()
		go func() { defer wg.Done(); _ = l.Close() }()
		wg.Wait()
		peer.Close()
		if got := listenerCounts(l); got != [4]int{} {
			t.Fatal("leaked or double-released permits", got)
		}
	}
}

// Model a socket already accepted by the OS but not delivered when Close wins.
type heldAcceptListener struct {
	net.Listener
	entered chan struct{}
	release chan struct{}
}

func (l *heldAcceptListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	close(l.entered)
	<-l.release
	return c, err
}

func TestListenerCloseDisposesUndeliveredSocket(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	held := &heldAcceptListener{Listener: ln, entered: make(chan struct{}), release: make(chan struct{})}
	l := newLimitedListener(held, 1)
	defer l.Close()
	result := make(chan error, 1)
	go func() { _, err := l.Accept(); result <- err }()
	peer, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	<-held.entered
	l.Close()
	close(held.release)
	if err := <-result; !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); err == nil {
		t.Fatal("undelivered socket leaked")
	}
	if got := listenerCounts(l); got != [4]int{} {
		t.Fatal(got)
	}
}

func TestListenerUnauthenticatedDeadlineAndPromotion(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := newLimitedListener(ln, 1)
	defer l.Close()
	peer, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	conn, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	c := conn.(*limitedConn)
	// A callback from the original TLS deadline must honor an extended PAKE
	// deadline instead of closing a still-valid handshake.
	r, _ := http.NewRequest(http.MethodGet, "https://localhost/v2/pair/start", nil)
	r = r.WithContext(context.WithValue(r.Context(), connectionKey{}, c))
	extendPairHandshake(r)
	c.expireUnauthenticated()
	if got := listenerCounts(l); got[0] != 1 {
		t.Fatal("old timer ignored extended deadline", got)
	}
	if err := c.promote(connectionPair); err != nil {
		t.Fatal(err)
	}
	c.expireUnauthenticated()
	if got := listenerCounts(l); got != [4]int{0, 0, 0, 1} {
		t.Fatal("old timer reclaimed authenticated pairing", got)
	}
	c.Close()
	peer2, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer peer2.Close()
	conn, err = l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	c = conn.(*limitedConn)
	l.mu.Lock()
	c.unauthDeadline = time.Now().Add(-time.Second)
	l.mu.Unlock()
	c.expireUnauthenticated()
	if got := listenerCounts(l); got != [4]int{} {
		t.Fatal("expired raw socket retained budget", got)
	}
	_ = peer2.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer2.Read(make([]byte, 1)); err == nil {
		t.Fatal("expired raw socket stayed open")
	}
}

func TestPauseWithSaturatedListenerReturnsWithinContext(t *testing.T) {
	_, _, _, controller, _ := setupShare(t)
	ctx := context.Background()
	if err := controller.Enable(ctx, EnableOptions{PointID: "p1"}); err != nil {
		t.Fatal(err)
	}
	s := controller.server.(*Server)
	l := s.ln.(*limitedListener)
	var raw []net.Conn
	defer func() {
		for _, c := range raw {
			c.Close()
		}
	}()
	for range MaxUnauthenticated + 2 {
		conn, err := net.DialTimeout("tcp", s.ListenAddress(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, conn)
	}
	waitRelay(t, "listener reaches unauthenticated capacity", func() bool { return listenerCounts(l)[0] == MaxUnauthenticated })
	bounded, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- controller.PauseSharing(bounded) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("Pause blocked behind listener capacity")
	}
	if got := listenerCounts(l); got != [4]int{} {
		t.Fatal(got)
	}
	if err := controller.ResumeSharing(ctx); err != nil {
		t.Fatal(err)
	}
	codeText, err := controller.ShareCode()
	if err != nil {
		t.Fatal(err)
	}
	code, _ := ParseShareCode(codeText)
	c, err := NewClient(ClientOptions{Code: code})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, _, err := c.Open(ctx); err != nil {
		t.Fatal("resume failed", err)
	}
}

func TestCloseWithSaturatedListenerReturnsWithinContext(t *testing.T) {
	fx := startShareFixture(t, "listener-close")
	var raw []net.Conn
	defer func() {
		for _, c := range raw {
			c.Close()
		}
	}()
	for range MaxUnauthenticated + MaxBusinessConnsTotal + 2 {
		conn, err := net.DialTimeout("tcp", fx.server.ListenAddress(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, conn)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- fx.server.Close(ctx) }()
	select {
	case <-done:
	case <-time.After(300 * time.Millisecond):
		t.Fatal("Close blocked behind listener capacity")
	}
}
