package localapps

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/qy/easyconnect/internal/model"
	"github.com/qy/easyconnect/internal/workeripc"
)

// Connections counts TCP streams through this project's entry, not OS-wide
// sockets or successful HTTP/database requests. A new launch starts at zero.
type Connections struct {
	Attempts, Connecting, Active, Opened, Failed uint64
	Sent, Received                               uint64
}

type connectionCounters struct {
	attempts, connecting, active, opened, failed atomic.Uint64
	sent, received                               atomic.Uint64
	lastNotify                                   atomic.Int64
	notifyPending                                atomic.Bool
}

func (s *connectionCounters) snapshot() Connections {
	return Connections{Attempts: s.attempts.Load(), Connecting: s.connecting.Load(), Active: s.active.Load(),
		Opened: s.opened.Load(), Failed: s.failed.Load(), Sent: s.sent.Load(), Received: s.received.Load()}
}

type AccessEvent struct {
	ID, Name, PointID, Mode, Target string
	Result                          workeripc.FlowResult
}

// Connection binds explicit launchers to a current VPN generation, just like
// capture. The optional fallback SOCKS address remains for existing callers.
type Connection struct {
	Dial   DialFunc
	Active func() bool
}

func (m *Manager) trackedDial(p model.LocalApp, r *run, dial DialFunc) DialFunc {
	return func(ctx context.Context, network, target string) (net.Conn, error) {
		s := &r.connections
		s.attempts.Add(1)
		s.connecting.Add(1)
		m.trafficChanged(r, false)
		c, err := dial(ctx, network, target)
		if c == nil && err == nil {
			err = errors.New("connection core returned no stream")
		}
		result := workeripc.ConnectionResult(c, err)
		if result.Target == "" {
			result.Target = target
		}
		s.connecting.Add(^uint64(0))
		if err != nil {
			s.failed.Add(1)
			if c != nil {
				_ = c.Close()
			}
			if result.Failure == "" {
				result.Failure = "connect"
			}
		} else {
			s.opened.Add(1)
			s.active.Add(1)
		}
		m.mu.Lock()
		current := m.runs[p.ID] == r && !m.closed && !r.view.Stopping && (r.view.Running || r.view.Starting)
		observer := m.onAccess
		m.mu.Unlock()
		if current && observer != nil {
			observer(AccessEvent{ID: p.ID, Name: p.Name, PointID: p.PointID, Mode: p.Mode, Target: target, Result: result})
		}
		m.trafficChanged(r, true)
		if err != nil {
			return nil, err
		}
		return &countedConn{Conn: c, counters: s, changed: func(force bool) { m.trafficChanged(r, force) }}, nil
	}
}

func (m *Manager) trafficChanged(r *run, force bool) {
	now := time.Now().UnixNano()
	last := r.connections.lastNotify.Load()
	if !force && (now-last < int64(250*time.Millisecond) || !r.connections.lastNotify.CompareAndSwap(last, now)) {
		// A quiet stream may never produce another byte or close. Queue one
		// trailing repaint so the last bytes in a burst still become visible.
		if r.connections.notifyPending.CompareAndSwap(false, true) {
			time.AfterFunc(250*time.Millisecond, func() {
				r.connections.notifyPending.Store(false)
				m.trafficChanged(r, true)
			})
		}
		return
	}
	if force {
		r.connections.lastNotify.Store(now)
	}
	m.mu.Lock()
	current := !m.closed && m.runs[r.view.ID] == r
	m.mu.Unlock()
	if current {
		m.notify()
	}
}

type countedConn struct {
	net.Conn
	counters *connectionCounters
	changed  func(bool)
	once     sync.Once
	closeErr error
}

func (c *countedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.counters.received.Add(uint64(n))
		c.changed(false)
	}
	return n, err
}
func (c *countedConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.counters.sent.Add(uint64(n))
		c.changed(false)
	}
	return n, err
}
func (c *countedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
func (c *countedConn) Close() error {
	c.once.Do(func() {
		c.closeErr = c.Conn.Close()
		c.counters.active.Add(^uint64(0))
		c.changed(true)
	})
	return c.closeErr
}
