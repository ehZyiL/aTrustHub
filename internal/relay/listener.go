package relay

import (
	"bufio"
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/ehzyil/connect-hub/internal/relay/contract"
)

type connectionKind uint8

const (
	connectionUnauthenticated connectionKind = iota
	connectionControl
	connectionTunnel
	connectionPair
)

type connectionKey struct{}

// Every socket starts in a reclaimable budget. A full budget evicts its
// oldest unauthenticated socket instead of blocking Accept: a new authorized
// peer must still be able to reach authentication. This is bounded admission,
// not a guarantee against continuous competing network traffic.
type limitedListener struct {
	net.Listener
	mu     sync.Mutex
	closed bool
	next   uint64
	conns  map[*limitedConn]uint64
	used   [4]int
	limits [4]int
}

func newLimitedListener(ln net.Listener, unauthenticated int) *limitedListener {
	return &limitedListener{Listener: ln, conns: make(map[*limitedConn]uint64), limits: [4]int{unauthenticated, MaxActiveClients * 4, MaxBusinessConnsTotal, contract.MaxPairRequests}}
}

func (l *limitedListener) Accept() (net.Conn, error) {
	raw, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		raw.Close()
		return nil, net.ErrClosed
	}
	var victim *limitedConn
	if l.used[connectionUnauthenticated] >= l.limits[connectionUnauthenticated] {
		var oldest uint64
		for c, sequence := range l.conns {
			if c.kind == connectionUnauthenticated && (victim == nil || sequence < oldest) {
				victim, oldest = c, sequence
			}
		}
		if victim != nil {
			victim.removeLocked()
		}
	}
	l.next++
	c := &limitedConn{Conn: raw, listener: l, unauthDeadline: time.Now().Add(TLSHandshakeTimeout)}
	l.conns[c] = l.next
	l.used[connectionUnauthenticated]++
	c.timer = time.AfterFunc(TLSHandshakeTimeout, c.expireUnauthenticated)
	l.mu.Unlock()
	if victim != nil {
		_ = victim.Conn.Close()
	}
	return c, nil
}

// Close also owns sockets accepted before delivery and hijacked sockets. No
// capacity wait or HTTP ownership handoff can hide them from shutdown.
func (l *limitedListener) Close() error {
	l.mu.Lock()
	l.closed = true
	all := make([]*limitedConn, 0, len(l.conns))
	for c := range l.conns {
		all = append(all, c)
		c.removeLocked()
	}
	l.mu.Unlock()
	err := l.Listener.Close()
	for _, c := range all {
		_ = c.Conn.Close()
	}
	return err
}

type limitedConn struct {
	net.Conn
	listener       *limitedListener
	kind           connectionKind
	closed         bool // all fields below the embedded socket are guarded by listener.mu
	timer          *time.Timer
	unauthDeadline time.Time
}

func (c *limitedConn) removeLocked() {
	if c.closed {
		return
	}
	c.closed = true
	delete(c.listener.conns, c)
	c.listener.used[c.kind]--
	if c.timer != nil {
		c.timer.Stop()
	}
}

func (c *limitedConn) Close() error {
	c.listener.mu.Lock()
	c.removeLocked()
	c.listener.mu.Unlock()
	return c.Conn.Close()
}

func (c *limitedConn) closeUnauthenticated() {
	c.listener.mu.Lock()
	closeSocket := !c.closed && c.kind == connectionUnauthenticated
	if closeSocket {
		c.removeLocked()
	}
	c.listener.mu.Unlock()
	if closeSocket {
		_ = c.Conn.Close()
	}
}

func (c *limitedConn) expireUnauthenticated() {
	c.listener.mu.Lock()
	if c.closed || c.kind != connectionUnauthenticated {
		c.listener.mu.Unlock()
		return
	}
	// A previously scheduled callback may already be running when pairing
	// extends its deadline. Recheck under the same lock as promotion/Close.
	if remaining := time.Until(c.unauthDeadline); remaining > 0 {
		c.timer.Reset(remaining)
		c.listener.mu.Unlock()
		return
	}
	c.removeLocked()
	c.listener.mu.Unlock()
	_ = c.Conn.Close()
}

func (c *limitedConn) promote(kind connectionKind) error {
	l := c.listener
	l.mu.Lock()
	defer l.mu.Unlock()
	if c.closed || l.closed {
		return net.ErrClosed
	}
	if c.kind == kind {
		return nil
	}
	if l.used[kind] >= l.limits[kind] {
		return NewError(CodeBusy, "连接资源繁忙，请稍后重试")
	}
	l.used[c.kind]--
	l.used[kind]++
	c.kind = kind
	if c.timer != nil {
		c.timer.Stop()
	}
	return nil
}

func managedConnection(conn net.Conn) *limitedConn {
	if tlsConn, ok := conn.(*tls.Conn); ok {
		conn = tlsConn.NetConn()
	}
	c, _ := conn.(*limitedConn)
	return c
}

func promoteConnection(r *http.Request, kind connectionKind) error {
	if c, _ := r.Context().Value(connectionKey{}).(*limitedConn); c != nil {
		return c.promote(kind)
	}
	return nil // isolated handler tests do not use a network listener
}

func extendPairHandshake(r *http.Request) {
	if c, _ := r.Context().Value(connectionKey{}).(*limitedConn); c != nil {
		c.listener.mu.Lock()
		if !c.closed && c.kind == connectionUnauthenticated {
			c.unauthDeadline = time.Now().Add(contract.PairHandshakeLifetime)
			c.timer.Reset(contract.PairHandshakeLifetime)
		}
		c.listener.mu.Unlock()
	}
}

// Announce closure before flushing a failed/unknown request. Closing only in
// StateIdle races the client's next non-idempotent request on the same socket.
type connectionResponse struct {
	http.ResponseWriter
	conn        *limitedConn
	wroteHeader bool
}

func (w *connectionResponse) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.conn.listener.mu.Lock()
	unauthenticated := w.conn.kind == connectionUnauthenticated
	w.conn.listener.mu.Unlock()
	if unauthenticated {
		w.Header().Set("Connection", "close")
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *connectionResponse) Write(data []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(data)
}

func (w *connectionResponse) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.ResponseWriter.(http.Hijacker).Hijack()
}

func (w *connectionResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }
