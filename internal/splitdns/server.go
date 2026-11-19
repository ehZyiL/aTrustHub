// Package splitdns provides a session-scoped loopback DNS transport. System DNS
// policy is installed separately; this listener alone changes no host settings.
package splitdns

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type ExchangeFunc func(context.Context, []byte) ([]byte, error)

type Server struct {
	ctx      context.Context
	cancel   context.CancelFunc
	tcp, udp *dns.Server
	listener net.Listener
	packet   net.PacketConn
	exchange ExchangeFunc
	slots    chan struct{}
	done     chan struct{}
	once     sync.Once
}

// Listen uses the same unprivileged loopback port for UDP and TCP. It neither
// caches nor rewrites TTLs; session disconnection cancels every in-flight query.
func Listen(parent context.Context, exchange ExchangeFunc) (*Server, error) {
	if exchange == nil {
		return nil, errors.New("DNS exchange function is required")
	}
	if err := parent.Err(); err != nil {
		return nil, err
	}
	// A TCP ephemeral port can already be in use for UDP; retry before giving up.
	var ln net.Listener
	var pc net.PacketConn
	var err error
	for range 8 {
		ln, err = net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		pc, err = net.ListenPacket("udp4", ln.Addr().String())
		if err == nil {
			break
		}
		ln.Close()
	}
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	s := &Server{ctx: ctx, cancel: cancel, listener: ln, packet: pc, exchange: exchange, slots: make(chan struct{}, 16), done: make(chan struct{})}
	tcpReady, udpReady := make(chan struct{}), make(chan struct{})
	s.tcp = &dns.Server{Listener: &limitedListener{Listener: ln, slots: make(chan struct{}, 32)}, Handler: s, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, IdleTimeout: func() time.Duration { return 5 * time.Second }, MaxTCPQueries: 32, NotifyStartedFunc: func() { close(tcpReady) }}
	s.udp = &dns.Server{PacketConn: pc, Handler: s, UDPSize: 4096, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, NotifyStartedFunc: func() { close(udpReady) }}
	errorsCh := make(chan error, 2)
	go func() { errorsCh <- s.tcp.ActivateAndServe() }()
	go func() { errorsCh <- s.udp.ActivateAndServe() }()
	for _, ready := range []chan struct{}{tcpReady, udpReady} {
		select {
		case <-ready:
		case err = <-errorsCh:
			s.Close()
			if err == nil {
				err = net.ErrClosed
			}
			return nil, err
		case <-ctx.Done():
			s.Close()
			return nil, ctx.Err()
		}
	}
	go func() {
		select {
		case <-ctx.Done():
		case <-errorsCh:
		}
		s.Close()
	}()
	return s, nil
}

func (s *Server) Addr() string          { return s.listener.Addr().String() }
func (s *Server) Done() <-chan struct{} { return s.done }

func (s *Server) ServeDNS(w dns.ResponseWriter, q *dns.Msg) {
	fail := func(code int) { m := new(dns.Msg).SetRcode(q, code); _ = w.WriteMsg(m) }
	if q.Response || q.Opcode != dns.OpcodeQuery || len(q.Question) != 1 {
		fail(dns.RcodeFormatError)
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		fail(dns.RcodeServerFailure)
		return
	}
	ctx, cancel := context.WithTimeout(s.ctx, 7*time.Second)
	defer cancel()
	packet, err := q.Pack()
	if err != nil {
		fail(dns.RcodeFormatError)
		return
	}
	packet, err = s.exchange(ctx, packet)
	if err != nil {
		fail(dns.RcodeServerFailure)
		return
	}
	m := new(dns.Msg)
	if len(packet) > 65535 || m.Unpack(packet) != nil || !m.Response || m.Id != q.Id || m.Opcode != q.Opcode || len(m.Question) != 1 ||
		!strings.EqualFold(m.Question[0].Name, q.Question[0].Name) || m.Question[0].Qtype != q.Question[0].Qtype || m.Question[0].Qclass != q.Question[0].Qclass {
		fail(dns.RcodeServerFailure)
		return
	}
	if _, udp := w.RemoteAddr().(*net.UDPAddr); udp {
		limit := 512
		if opt := q.IsEdns0(); opt != nil {
			limit = int(opt.UDPSize())
			if limit < 512 {
				limit = 512
			}
			if limit > 4096 {
				limit = 4096
			}
		}
		m.Truncate(limit)
	}
	_ = w.WriteMsg(m)
}

func (s *Server) Close() error {
	s.once.Do(func() {
		s.cancel()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		var wg sync.WaitGroup
		for _, server := range []*dns.Server{s.tcp, s.udp} {
			if server != nil {
				wg.Add(1)
				go func(d *dns.Server) { defer wg.Done(); _ = d.ShutdownContext(ctx) }(server)
			}
		}
		wg.Wait()
		_ = s.listener.Close()
		_ = s.packet.Close()
		close(s.done)
	})
	return nil
}

type limitedListener struct {
	net.Listener
	slots chan struct{}
}

func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &limitedConn{Conn: c, release: func() { <-l.slots }}, nil
		default:
			c.Close()
		}
	}
}

type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConn) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }
