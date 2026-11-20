package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	datagramPreface = 0xf5
	MaxDatagram     = 65507
	datagramIdle    = 60 * time.Second
)

// The private helper link uses an authenticated, length-prefixed stream. The
// prefix gives framing one meaning without extending public SOCKS5 commands.
func (s *Server) handleDatagrams(conn net.Conn, br *bufio.Reader) {
	select {
	case s.packets <- struct{}{}:
		defer func() { <-s.packets }()
	default:
		return
	}
	_, _ = br.ReadByte()
	if s.negotiate(conn, br) != nil {
		return
	}
	address, err := s.request(conn, br)
	target, parseErr := netip.ParseAddrPort(address)
	if err != nil || parseErr != nil || !target.Addr().Is4() || target.Port() == 0 {
		return
	}
	parent := s.opts.Context
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	upstream, err := s.opts.DialDatagram(ctx, target.String())
	cancel()
	if err != nil {
		_ = s.reply(conn, replyHostUnreachable)
		return
	}
	defer upstream.Close()
	if !s.track(upstream) {
		return
	}
	defer s.untrack(upstream)
	if err := s.reply(conn, replySuccess); err != nil {
		return
	}
	RelayDatagrams(parent, &datagramStream{Conn: conn, reader: br}, upstream)
}

// DialDatagramContext pins one private link to one captured IPv4 target. It
// never falls back to a standard SOCKS CONNECT or to the host network.
func (d *SOCKSDialer) DialDatagramContext(ctx context.Context, address string) (net.Conn, error) {
	peer, peerErr := netip.ParseAddrPort(d.address)
	target, targetErr := netip.ParseAddrPort(address)
	if peerErr != nil || peer.Addr() != netip.AddrFrom4([4]byte{127, 0, 0, 1}) || peer.Port() == 0 || targetErr != nil || !target.Addr().Is4() || target.Port() == 0 || d.auth == nil || len(d.auth.User) == 0 || len(d.auth.User) > 255 || len(d.auth.Password) == 0 || len(d.auth.Password) > 255 {
		return nil, errors.New("proxy: invalid private datagram endpoints or credentials")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp4", d.address)
	if err != nil {
		return nil, err
	}
	ready := false
	defer func() {
		if !ready {
			_ = conn.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	if _, err = conn.Write([]byte{datagramPreface, 5, 1, 2}); err != nil {
		return nil, err
	}
	var authReply [2]byte
	if _, err = io.ReadFull(conn, authReply[:]); err != nil || authReply != [2]byte{5, 2} {
		return nil, errors.New("proxy: helper datagram authentication unavailable")
	}
	credentials := append([]byte{1, byte(len(d.auth.User))}, d.auth.User...)
	credentials = append(credentials, byte(len(d.auth.Password)))
	credentials = append(credentials, d.auth.Password...)
	if _, err = conn.Write(credentials); err != nil {
		return nil, err
	}
	if _, err = io.ReadFull(conn, authReply[:]); err != nil || authReply != [2]byte{1, 0} {
		return nil, errors.New("proxy: helper datagram authentication failed")
	}
	ip := target.Addr().As4()
	request := binary.BigEndian.AppendUint16([]byte{5, 1, 0, 1, ip[0], ip[1], ip[2], ip[3]}, target.Port())
	if _, err = conn.Write(request); err != nil {
		return nil, err
	}
	var reply [10]byte
	if _, err = io.ReadFull(conn, reply[:]); err != nil || reply != [10]byte{5, 0, 0, 1} {
		return nil, errors.New("proxy: helper datagram destination refused")
	}
	if !stop() || ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	if err = conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	ready = true
	return &datagramStream{Conn: conn, reader: conn}, nil
}

type datagramStream struct {
	net.Conn
	reader  io.Reader
	readMu  sync.Mutex
	writeMu sync.Mutex
}

func (c *datagramStream) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	var header [2]byte
	if _, err := io.ReadFull(c.reader, header[:]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(header[:]))
	if n > MaxDatagram || n > len(p) {
		_ = c.Close()
		return 0, io.ErrShortBuffer
	}
	return io.ReadFull(c.reader, p[:n])
}

func (c *datagramStream) Write(p []byte) (int, error) {
	if len(p) > MaxDatagram {
		return 0, errors.New("proxy: datagram too large")
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	frame := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(frame, uint16(len(p)))
	copy(frame[2:], p)
	if _, err := c.Conn.Write(frame); err != nil {
		_ = c.Close()
		return 0, err
	}
	return len(p), nil
}

// RelayDatagrams writes each read as one packet, including empty packets. An
// error, idle timeout or cancellation closes both directions.
func RelayDatagrams(ctx context.Context, a, b net.Conn) {
	closeBoth := sync.OnceFunc(func() { _ = a.Close(); _ = b.Close() })
	stop := context.AfterFunc(ctx, closeBoth)
	defer stop()
	refresh := func() {
		until := time.Now().Add(datagramIdle)
		_ = a.SetDeadline(until)
		_ = b.SetDeadline(until)
	}
	refresh()
	relay := func(dst, src net.Conn) {
		defer closeBoth()
		p := make([]byte, MaxDatagram)
		for {
			n, err := src.Read(p)
			if err != nil {
				return
			}
			refresh()
			if written, err := dst.Write(p[:n]); err != nil || written != n {
				return
			}
		}
	}
	done := make(chan struct{})
	go func() { defer close(done); relay(a, b) }()
	relay(b, a)
	<-done
}
