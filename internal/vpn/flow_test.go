package vpn

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ehZyiL/connect-hub/internal/model"
	"github.com/ehZyiL/connect-hub/internal/workeripc"
	"github.com/things-go/go-socks5"
)

type testFlowCredentials struct{ password string }

func (c testFlowCredentials) Valid(user, password, _ string) bool {
	expected := c.password
	if expected == "" {
		expected = "fixture-only"
	}
	return strings.HasPrefix(user, "hub/") && password == expected
}

func runFlowWorkerFixture(start workeripc.Message, decoder *json.Decoder, emit func(workeripc.Message)) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		os.Exit(5)
	}
	defer ln.Close()
	server := socks5.NewServer(socks5.WithAuthMethods([]socks5.Authenticator{socks5.UserPassAuthenticator{Credentials: testFlowCredentials{password: start.Config.SocksPassword}}}), socks5.WithDialAndRequest(func(_ context.Context, _, addr string, req *socks5.Request) (net.Conn, error) {
		r := workeripc.FlowResult{Target: addr, Route: "direct", Rule: "default"}
		if addr != "127.0.0.1:12001" {
			r.Route, r.Rule, r.Failure = "blocked", "acl", "denied"
		}
		if addr == "127.0.0.1:12003" {
			r.Target, r.Route, r.Failure = "invalid\nreport:443", "direct", ""
		}
		emit(workeripc.Message{Type: "flow_result", RequestID: testFlowID(req), Flow: &r})
		if r.Failure != "" {
			return nil, errors.New("fixture denied")
		}
		a, b := net.Pipe()
		go func() { defer b.Close(); io.WriteString(b, "fixture") }()
		return testAddrConn{a}, nil
	}))
	go server.Serve(ln)
	emit(workeripc.Message{Type: "ready", Address: ln.Addr().String(), FlowReporting: true})
	var request workeripc.Message
	for decoder.Decode(&request) == nil {
	}
}

func TestFlowResultsThroughWorkerControlPipe(t *testing.T) {
	t.Setenv("EASYCONNECT_TEST_WORKER", "flows")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	sess, err := NewEasyConnectConnector(exe)(context.Background(), model.AccessPoint{Server: "fixture.invalid", Port: 443}, Credentials{Login: "test-password", Challenge: func(context.Context, Challenge) (string, error) { return "test-code", nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			target := "127.0.0.1:12001"
			if i%2 == 0 {
				target = "127.0.0.1:12002"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			c, err := sess.Dial(ctx, "tcp", target)
			r := workeripc.ConnectionResult(c, err)
			if r.Target != target || (r.Failure == "denied") != (i%2 == 0) || (err != nil) != (i%2 == 0) {
				t.Errorf("pipe correlation: %+v %v", r, err)
			}
			if c != nil {
				io.ReadAll(c)
				c.Close()
			}
		}(i)
	}
	wg.Wait()
	// A malformed advisory report must not kill the whole VPN. It times out
	// to unknown for this request; later valid reports remain usable.
	for _, test := range []struct{ target, route string }{{"127.0.0.1:12003", "unknown"}, {"127.0.0.1:12001", "direct"}} {
		c, err := sess.Dial(context.Background(), "tcp", test.target)
		if err != nil {
			t.Fatal(err)
		}
		r := workeripc.ConnectionResult(c, err)
		io.ReadAll(c)
		c.Close()
		if r.Route != test.route {
			t.Fatalf("malformed report affected session: %+v", r)
		}
	}
}

func flowTestSession(t *testing.T, dial func(context.Context, string, string, *socks5.Request, *flowDials) (net.Conn, error)) *processSession {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &processSession{done: make(chan struct{}), stopping: make(chan struct{})}
	f := newFlowDials(ln.Addr().String(), "hub", "fixture-only")
	s.flows.Store(f)
	server := socks5.NewServer(socks5.WithAuthMethods([]socks5.Authenticator{socks5.UserPassAuthenticator{Credentials: testFlowCredentials{}}}), socks5.WithDialAndRequest(func(ctx context.Context, network, address string, r *socks5.Request) (net.Conn, error) {
		return dial(ctx, network, address, r, f)
	}))
	go server.Serve(ln)
	return s
}

func testFlowID(req *socks5.Request) string {
	return strings.TrimPrefix(req.AuthContext.Payload["username"], "hub/")
}

func TestFlowConcurrentDialsAndFailuresAreCorrelated(t *testing.T) {
	s := flowTestSession(t, func(_ context.Context, _, address string, req *socks5.Request, f *flowDials) (net.Conn, error) {
		_, port, _ := net.SplitHostPort(address)
		n, _ := strconv.Atoi(port)
		time.Sleep(time.Duration(n%7) * time.Millisecond)
		r := workeripc.FlowResult{Target: address, Route: "direct", Rule: "default"}
		if n%2 == 0 {
			r.Route, r.Rule, r.Failure = "blocked", "acl", "denied"
		}
		if !f.deliver(workeripc.Message{RequestID: testFlowID(req), Flow: &r}) {
			t.Error("valid report rejected")
		}
		if n%2 == 0 {
			return nil, errors.New("denied")
		}
		a, b := net.Pipe()
		go func() { defer b.Close(); io.WriteString(b, "test") }()
		return testAddrConn{a}, nil
	})
	var wg sync.WaitGroup
	for i := 1; i <= 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			target := net.JoinHostPort("127.0.0.1", strconv.Itoa(10000+i))
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			conn, err := s.Dial(ctx, "tcp", target)
			r := workeripc.ConnectionResult(conn, err)
			if r.Target != target || (r.Failure == "denied") != (i%2 == 0) || (err != nil) != (i%2 == 0) {
				t.Errorf("wrong result %s %+v %v", target, r, err)
			}
			if conn != nil {
				io.ReadAll(conn)
				conn.Close()
			}
		}(i)
	}
	wg.Wait()
	f := s.flows.Load()
	f.mu.Lock()
	pending := len(f.pending)
	f.mu.Unlock()
	if pending != 0 || len(f.slots) != 0 {
		t.Fatal("pending requests leaked")
	}
}

type testAddrConn struct{ net.Conn }

func (c testAddrConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
}

func TestFlowReportAndCountingDoNotHideTCPHalfClose(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, e := ln.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		b, e := io.ReadAll(c)
		if e == nil {
			c.Write(append([]byte("response:"), b...))
		}
	}()
	s := flowTestSession(t, func(ctx context.Context, network, address string, req *socks5.Request, f *flowDials) (net.Conn, error) {
		c, e := (&net.Dialer{}).DialContext(ctx, network, address)
		r := workeripc.FlowResult{Target: address, Route: "direct", Rule: "default"}
		if e != nil {
			r.Failure = "connect"
		}
		f.deliver(workeripc.Message{RequestID: testFlowID(req), Flow: &r})
		return c, e
	})
	c, err := s.Dial(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	io.WriteString(c, "query")
	cw, ok := c.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("CloseWrite hidden")
	}
	cw.CloseWrite()
	b, err := io.ReadAll(c)
	if err != nil || string(b) != "response:query" {
		t.Fatalf("half-close lost: %q %v", b, err)
	}
}

func TestFlowMissingAndLateReportsDoNotRetagConnections(t *testing.T) {
	var oldID string
	var mu sync.Mutex
	s := flowTestSession(t, func(_ context.Context, _, addr string, req *socks5.Request, f *flowDials) (net.Conn, error) {
		mu.Lock()
		defer mu.Unlock()
		id := testFlowID(req)
		if oldID == "" {
			oldID = id
		} else {
			late := workeripc.FlowResult{Target: "127.0.0.1:9999", Route: "vpn", Rule: "forced"}
			f.deliver(workeripc.Message{RequestID: oldID, Flow: &late})
			current := workeripc.FlowResult{Target: addr, Route: "direct", Rule: "default"}
			f.deliver(workeripc.Message{RequestID: id, Flow: &current})
		}
		a, b := net.Pipe()
		go func() { b.Close() }()
		return testAddrConn{a}, nil
	})
	for i, want := range []string{"unknown", "direct"} {
		c, err := s.Dial(context.Background(), "tcp", "127.0.0.1:"+strconv.Itoa(9000+i))
		if err != nil {
			t.Fatal(err)
		}
		r := workeripc.ConnectionResult(c, nil)
		c.Close()
		if r.Route != want {
			t.Fatalf("late/missing result retagged stream: %+v", r)
		}
	}
}

func TestFlowSlotsRespectCancellation(t *testing.T) {
	s := &processSession{done: make(chan struct{}), stopping: make(chan struct{})}
	f := newFlowDials("127.0.0.1:1", "hub", "unused")
	s.flows.Store(f)
	for i := 0; i < cap(f.slots); i++ {
		f.slots <- struct{}{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Dial(ctx, "tcp", "127.0.0.1:2"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if len(f.pending) != 0 {
		t.Fatal("canceled request registered")
	}
}

func TestFlowHubEmitsCancelOnTimeout(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	server := socks5.NewServer(
		socks5.WithAuthMethods([]socks5.Authenticator{socks5.UserPassAuthenticator{Credentials: testFlowCredentials{}}}),
		socks5.WithDialAndRequest(func(ctx context.Context, _, _ string, _ *socks5.Request) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}),
	)
	go server.Serve(ln)

	s := &processSession{
		done:     make(chan struct{}),
		stopping: make(chan struct{}),
		outgoing: make(chan workerWrite, 16),
		session:  "test-session",
	}
	f := newFlowDials(ln.Addr().String(), "hub", "fixture-only")
	s.flows.Store(f)

	dialCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, dialErr := s.dialFlow(dialCtx, "127.0.0.1:9999")
	if dialErr == nil {
		t.Fatal("dial should have timed out")
	}

	select {
	case req := <-s.outgoing:
		if req.message.Type != "flow_cancel" || req.message.RequestID != "1" {
			t.Fatalf("unexpected message on outgoing: %+v", req.message)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected flow_cancel message on outgoing pipe, got none")
	}

	if len(f.slots) != 0 {
		t.Fatalf("hub slot leaked: len=%d", len(f.slots))
	}
}

func TestFlowProcessSessionReadyParsesVPNAddress(t *testing.T) {
	s := &processSession{}
	err := s.configureReady(workeripc.Message{
		Address: "127.0.0.1:12001", VPNAddress: "127.0.0.1:12002",
		Capabilities: []string{"strict_vpn", "flow_cancel", "flow_prepare"}, FlowReporting: true,
	}, "fixture-only")
	if err != nil {
		t.Fatal(err)
	}
	f := s.flows.Load()
	if f.address != "127.0.0.1:12001" || f.vpnAddress != "127.0.0.1:12002" || !f.prepare {
		t.Fatalf("ordinary/strict entry configuration: ordinary=%s strict=%s prepared=%v", f.address, f.vpnAddress, f.prepare)
	}
}
