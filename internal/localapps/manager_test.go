package localapps

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/ehZyiL/connect-hub/internal/model"
	"github.com/ehZyiL/connect-hub/internal/proxy"
)

func forwardProfile() model.LocalApp {
	return model.LocalApp{ID: "db", Name: "test db", PointID: "point", Mode: model.LocalAppTCPForward, RemoteAddress: "database.internal:5432"}
}

func TestForwardPreservesTargetAndHalfClose(t *testing.T) {
	backend, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		c, err := backend.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		body, _ := io.ReadAll(c)
		_, _ = c.Write(append([]byte("reply:"), body...))
	}()
	targets := make(chan string, 1)
	p := proxy.New(proxy.Options{Addr: "127.0.0.1:0", Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		targets <- address
		return (&net.Dialer{}).DialContext(ctx, network, backend.Addr().String())
	}})
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	m := NewManager(nil)
	defer m.Close()
	if err := m.Start(forwardProfile(), p.Addr().String()); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(forwardProfile(), p.Addr().String()); err == nil {
		t.Fatal("duplicate start accepted")
	}
	v := m.View("db")
	c, err := net.DialTimeout("tcp4", v.LocalAddress, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = io.WriteString(c, "query")
	_ = c.(*net.TCPConn).CloseWrite()
	body, err := io.ReadAll(c)
	if err != nil || string(body) != "reply:query" {
		t.Fatalf("response=%q error=%v", body, err)
	}
	if got := <-targets; got != "database.internal:5432" {
		t.Fatalf("SOCKS target=%s", got)
	}
	m.StopPoint("different-point")
	if !m.View("db").Running {
		t.Fatal("different point stopped forward")
	}
	m.StopPoint("point")
	if m.View("db").Running {
		t.Fatal("forward still running")
	}
	ln, err := net.Listen("tcp4", v.LocalAddress)
	if err != nil {
		t.Fatalf("listener not released: %v", err)
	}
	_ = ln.Close()
	if err := m.Start(forwardProfile(), p.Addr().String()); err != nil {
		t.Fatalf("restart: %v", err)
	}
}

func TestForwardFailureDoesNotDialTargetDirectly(t *testing.T) {
	backend, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	p := proxy.New(proxy.Options{Addr: "127.0.0.1:0", Dial: func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("upstream unavailable")
	}})
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	m := NewManager(nil)
	defer m.Close()
	profile := forwardProfile()
	profile.RemoteAddress = backend.Addr().String()
	if err := m.Start(profile, p.Addr().String()); err != nil {
		t.Fatal(err)
	}
	c, err := net.DialTimeout("tcp4", m.View(profile.ID).LocalAddress, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = c.Write([]byte("hello"))
	if _, err = c.Read(make([]byte, 1)); err == nil {
		t.Fatal("failed upstream did not close client")
	}
	_ = backend.(*net.TCPListener).SetDeadline(time.Now().Add(100 * time.Millisecond))
	if conn, err := backend.Accept(); err == nil {
		conn.Close()
		t.Fatal("unexpected direct fallback")
	}
}

func TestStopInterruptsSOCKSHandshake(t *testing.T) {
	blackhole, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blackhole.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := blackhole.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	m := NewManager(nil)
	defer m.Close()
	if err := m.Start(forwardProfile(), blackhole.Addr().String()); err != nil {
		t.Fatal(err)
	}
	c, err := net.DialTimeout("tcp4", m.View("db").LocalAddress, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	select {
	case upstream := <-accepted:
		defer upstream.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("dial did not reach SOCKS")
	}
	done := make(chan struct{})
	go func() { _ = m.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Close blocked on SOCKS handshake")
	}
	if err := m.Start(forwardProfile(), blackhole.Addr().String()); err == nil {
		t.Fatal("start accepted after close")
	}
}
