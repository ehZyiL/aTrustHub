package capture

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestCloseCancelsPendingDial(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	s := serveTCP(context.Background(), ln, func(ctx context.Context, _, _ string) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	t.Cleanup(func() { _ = s.Close() })
	c, err := net.DialTimeout("tcp", s.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream dial did not start")
	}
	closed := make(chan struct{})
	go func() { _ = s.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not cancel upstream dial")
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("client connection remained open")
	}
}

func TestRelayPreservesResponseAfterRequestEOF(t *testing.T) {
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
		_, _ = c.Write(append([]byte("response:"), body...))
	}()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := serveTCP(context.Background(), ln, func(ctx context.Context, _, address string) (net.Conn, error) {
		if address != ln.Addr().String() {
			t.Errorf("target = %s", address)
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp4", backend.Addr().String())
	})
	defer s.Close()
	c, err := net.DialTimeout("tcp4", s.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = io.WriteString(c, "hello")
	_ = c.(*net.TCPConn).CloseWrite()
	body, err := io.ReadAll(c)
	if err != nil || string(body) != "response:hello" {
		t.Fatalf("response = %q, error = %v", body, err)
	}
}
