// Package capture implements the experimental Linux per-application TCP helper.
// DNS and host coexistence still need validation before general release.
package capture

import (
	"context"
	"errors"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/qy/easyconnect/internal/proxy"
	"github.com/sagernet/sing/common/control"
	"golang.org/x/sys/unix"
)

// DialFunc must honor cancellation and is usually an authenticated SOCKS
// dialer. The ingress has no direct fallback when that dialer fails.
type DialFunc func(context.Context, string, string) (net.Conn, error)

// TCP is an IPv4 transparent listener. Rule installation is a separate concern;
// callers must remove their capture rules before closing the listener.
type TCP struct {
	ln     net.Listener
	dial   DialFunc
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once
	wg     sync.WaitGroup
	mu     sync.Mutex
	closed bool
	conns  map[net.Conn]struct{}
}

// ListenTCP creates a loopback-only transparent listener using sing's existing
// socket controls. CAP_NET_ADMIN or CAP_NET_RAW in the network namespace is
// required. For TPROXY, an accepted socket's LocalAddr is the original target.
func ListenTCP(ctx context.Context, address string, dial DialFunc) (*TCP, error) {
	if dial == nil {
		return nil, errors.New("capture: no upstream dialer")
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil || host != "127.0.0.1" {
		return nil, errors.New("capture: listener must bind 127.0.0.1")
	}
	lc := net.ListenConfig{Control: func(_, _ string, conn syscall.RawConn) error {
		return control.Raw(conn, func(fd uintptr) error { return control.TProxy(fd, unix.AF_INET) })
	}}
	ln, err := lc.Listen(ctx, "tcp4", address)
	if err != nil {
		return nil, err
	}
	return serveTCP(ctx, ln, dial), nil
}

func serveTCP(ctx context.Context, ln net.Listener, dial DialFunc) *TCP {
	ctx, cancel := context.WithCancel(ctx)
	s := &TCP{ln: ln, dial: dial, ctx: ctx, cancel: cancel, done: make(chan struct{}), conns: make(map[net.Conn]struct{})}
	go s.accept()
	go func() {
		select {
		case <-ctx.Done():
		case <-s.done:
		}
		s.Close()
	}()
	return s
}

func (s *TCP) Addr() net.Addr { return s.ln.Addr() }

func (s *TCP) accept() {
	defer close(s.done)
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		if !s.track(conn) {
			_ = conn.Close()
			return
		}
		s.wg.Add(1)
		go func() { defer s.wg.Done(); s.handle(conn) }()
	}
}

func (s *TCP) handle(conn net.Conn) {
	defer s.release(conn)
	ctx, cancel := context.WithTimeout(s.ctx, 15*time.Second)
	upstream, err := s.dial(ctx, "tcp", conn.LocalAddr().String())
	cancel()
	if err != nil {
		return
	}
	if !s.track(upstream) {
		_ = upstream.Close()
		return
	}
	defer s.release(upstream)
	proxy.Relay(conn, upstream)
}

func (s *TCP) track(conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.conns[conn] = struct{}{}
	return true
}

func (s *TCP) release(conn net.Conn) {
	_ = conn.Close()
	s.mu.Lock()
	delete(s.conns, conn)
	s.mu.Unlock()
}

// Close cancels pending upstream dials and drains all accepted connections.
func (s *TCP) Close() error {
	s.once.Do(func() {
		s.cancel()
		s.mu.Lock()
		s.closed = true
		conns := make([]net.Conn, 0, len(s.conns))
		for conn := range s.conns {
			conns = append(conns, conn)
		}
		s.mu.Unlock()
		_ = s.ln.Close()
		for _, conn := range conns {
			_ = conn.Close()
		}
		<-s.done
		s.wg.Wait()
	})
	return nil
}
