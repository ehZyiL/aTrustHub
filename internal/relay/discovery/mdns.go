package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
)

// errTimeout means "no packet arrived before the deadline", which every read
// loop uses to reach its housekeeping step. It is not a failure.
var errTimeout = errors.New("discovery: read timeout")

// link is one interface's transport. The production implementation is a
// multicast UDP socket; tests replace it with an in-memory hub so the protocol,
// the cache and the lifecycle can be exercised deterministically without
// depending on a real multicast-capable network.
type link interface {
	Send(b []byte) error
	// Receive blocks until a packet arrives or the deadline passes. A deadline
	// returns errTimeout.
	Receive(b []byte) (int, error)
	SetReadDeadline(t time.Time) error
	Close() error
}

// mdnsBackend speaks multicast DNS on real sockets.
type mdnsBackend struct {
	open func(Interface) (link, error)
	logf func(string, ...any)
	now  func() time.Time
}

// NewMDNSBackend returns the production backend: one multicast socket per
// selected interface, group 224.0.0.251 port 5353.
func NewMDNSBackend(logf func(string, ...any)) Backend {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &mdnsBackend{open: openMulticast, logf: logf, now: time.Now}
}

// ---- advertising ---------------------------------------------------------

type registration struct {
	link link
	ann  Announcement
	logf func(string, ...any)
	now  func() time.Time

	closeOnce sync.Once
	done      chan struct{}
	loopDone  chan struct{}
	closeErr  error
}

// Advertise registers one announcement. Only the running share calls this: the
// announcement carries the address and port that actually bound.
func (b *mdnsBackend) Advertise(ctx context.Context, a Announcement) (Registration, error) {
	if err := a.Validate(); err != nil {
		return nil, err
	}
	l, err := b.open(a.Interface)
	if err != nil {
		return nil, err
	}
	reg := &registration{
		link: l, ann: a, logf: b.logf, now: b.now,
		done: make(chan struct{}), loopDone: make(chan struct{}),
	}
	// RFC 6762 section 8.3: announce at least twice, one second apart, so a
	// lost packet does not cost a colleague the whole TTL.
	if err := reg.send(false); err != nil {
		_ = l.Close()
		return nil, err
	}
	go reg.loop()
	return reg, nil
}

func (r *registration) send(goodbye bool) error {
	b, err := announcementMessage(r.ann, goodbye).Pack()
	if err != nil {
		return err
	}
	return r.link.Send(b)
}

func (r *registration) loop() {
	defer close(r.loopDone)
	second := time.NewTimer(time.Second)
	defer second.Stop()
	// Re-announce halfway through the host-name TTL so the records never
	// expire while the share is up.
	refresh := time.NewTicker(TTLHost / 2)
	defer refresh.Stop()
	buf := make([]byte, 9000)
	for {
		select {
		case <-r.done:
			return
		case <-second.C:
			_ = r.send(false)
		case <-refresh.C:
			_ = r.send(false)
		default:
		}
		_ = r.link.SetReadDeadline(r.now().Add(500 * time.Millisecond))
		n, err := r.link.Receive(buf)
		if err != nil {
			if errors.Is(err, errTimeout) {
				continue
			}
			select {
			case <-r.done:
				return
			default:
			}
			r.logf("局域网发现：接收失败：%v", err)
			return
		}
		r.answer(buf[:n])
	}
}

// answer responds to queries for our own names only. Nothing else is served:
// this is not a general-purpose responder.
func (r *registration) answer(packet []byte) {
	var msg dns.Msg
	if err := msg.Unpack(packet); err != nil || msg.Response {
		return
	}
	instance := InstanceName(r.ann.ShareID)
	host := HostLabel(r.ann.ShareID)
	want := false
	for _, q := range msg.Question {
		name := q.Name
		switch {
		case q.Qtype == dns.TypePTR && equalName(name, ServiceType):
			want = true
		case (q.Qtype == dns.TypeSRV || q.Qtype == dns.TypeTXT) && equalName(name, instance):
			want = true
		case q.Qtype == dns.TypeA && equalName(name, host):
			want = true
		}
	}
	if !want {
		return
	}
	reply := announcementMessage(r.ann, false)
	// A response to a query echoes the query ID (0 for mDNS) and repeats the
	// question so resolvers can match it.
	reply.Id = msg.Id
	reply.Question = msg.Question
	b, err := reply.Pack()
	if err != nil {
		return
	}
	_ = r.link.Send(b)
}

// Close withdraws the announcement. The goodbye is sent twice because a single
// lost multicast packet would otherwise leave the entry in every cache until
// its TTL expires.
func (r *registration) Close() error {
	r.closeOnce.Do(func() {
		close(r.done)
		err := r.send(true)
		if err == nil {
			err = r.send(true)
		}
		_ = r.link.Close()
		<-r.loopDone
		r.closeErr = err
	})
	return r.closeErr
}

// equalName compares two DNS names the way the protocol does: case-insensitive
// and with an optional trailing dot.
func equalName(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

// ---- browsing ------------------------------------------------------------

// browsedLink pairs a transport with the interface it belongs to, so every
// record can be attributed to where it actually arrived.
type browsedLink struct {
	link link
	ifi  Interface
}

type browseSession struct {
	links []browsedLink
	opts  BrowseOptions
	logf  func(string, ...any)
	now   func() time.Time

	closeOnce sync.Once
	done      chan struct{}
	refresh   chan struct{}
	wg        sync.WaitGroup
}

// Browse starts one browsing session. An empty interface list is an error: the
// feature never browses a scope the user did not choose.
func (b *mdnsBackend) Browse(ctx context.Context, opts BrowseOptions) (Session, error) {
	if len(opts.Interfaces) == 0 {
		return nil, errors.New("没有可用的局域网网卡")
	}
	if opts.OnRecords == nil {
		return nil, errors.New("缺少结果回调")
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	links := make([]browsedLink, 0, len(opts.Interfaces))
	for _, ifi := range opts.Interfaces {
		if !ifi.Valid() {
			for _, l := range links {
				_ = l.link.Close()
			}
			return nil, fmt.Errorf("网卡不合法：%s", ifi)
		}
		l, err := b.open(ifi)
		if err != nil {
			for _, done := range links {
				_ = done.link.Close()
			}
			return nil, fmt.Errorf("无法在 %s 上监听发现请求：%w", ifi, err)
		}
		links = append(links, browsedLink{link: l, ifi: ifi})
	}
	s := &browseSession{
		links: links, opts: opts, logf: opts.Logf, now: b.now,
		done: make(chan struct{}), refresh: make(chan struct{}, 1),
	}
	s.wg.Add(1)
	go s.queryLoop()
	for _, l := range links {
		s.wg.Add(1)
		go s.readLoop(l)
	}
	return s, nil
}

func (s *browseSession) Refresh() error {
	select {
	case s.refresh <- struct{}{}:
	default:
	}
	return nil
}

func (s *browseSession) queryLoop() {
	defer s.wg.Done()
	// Exponential back-off capped at one minute, exactly the shape RFC 6762
	// suggests for continuous queries.
	send := func() {
		b, err := browseQuery().Pack()
		if err != nil {
			return
		}
		for _, l := range s.links {
			_ = l.link.Send(b)
		}
	}
	send()
	delay := time.Second
	timer := time.NewTimer(delay)
	defer timer.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-timer.C:
			send()
			if delay < time.Minute {
				delay *= 2
				if delay > time.Minute {
					delay = time.Minute
				}
			}
			timer.Reset(delay)
		case <-s.refresh:
			// A user-visible refresh re-queries immediately but keeps the
			// existing cache.
			send()
		}
	}
}

func (s *browseSession) readLoop(l browsedLink) {
	defer s.wg.Done()
	buf := make([]byte, 9000)
	for {
		_ = l.link.SetReadDeadline(s.now().Add(500 * time.Millisecond))
		n, err := l.link.Receive(buf)
		if err != nil {
			if errors.Is(err, errTimeout) {
				select {
				case <-s.done:
					return
				default:
					continue
				}
			}
			select {
			case <-s.done:
				return
			default:
			}
			return
		}
		var msg dns.Msg
		if err := msg.Unpack(buf[:n]); err != nil {
			continue
		}
		if !msg.Response {
			continue
		}
		records := parseRecords(&msg, l.ifi.Name)
		for _, rec := range records {
			// Ask for the records a bare PTR may not carry. This is one extra
			// query per new instance, not a scan.
			if rec.Kind == KindPTR && !rec.Gone() {
				if b, err := instanceQuery(rec.Instance).Pack(); err == nil {
					_ = l.link.Send(b)
				}
			}
		}
		if len(records) > 0 {
			s.opts.OnRecords(records)
		}
	}
}

func (s *browseSession) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
		for _, l := range s.links {
			_ = l.link.Close()
		}
		s.wg.Wait()
	})
	return nil
}

// ---- production socket ---------------------------------------------------

// openMulticast opens one multicast DNS socket bound to the given interface.
// The socket joins 224.0.0.251 and sends from the same interface, so a machine
// with several networks never leaks an announcement to the wrong one.
func openMulticast(ifi Interface) (link, error) {
	nif, err := net.InterfaceByName(ifi.Name)
	if err != nil {
		return nil, err
	}
	group := &net.UDPAddr{IP: net.ParseIP(mdnsGroupIP), Port: mdnsPort}
	conn, err := net.ListenMulticastUDP("udp4", nif, group)
	if err != nil {
		return nil, err
	}
	pc := ipv4.NewPacketConn(conn)
	if err := pc.SetControlMessage(ipv4.FlagInterface|ipv4.FlagDst, true); err != nil {
		_ = pc.Close()
		return nil, err
	}
	// Outgoing multicast must leave through this interface only.
	if err := pc.SetMulticastInterface(nif); err != nil {
		_ = pc.Close()
		return nil, err
	}
	if err := pc.SetMulticastTTL(255); err != nil {
		_ = pc.Close()
		return nil, err
	}
	// Loopback lets two instances on one machine see each other, which is what
	// the developer's own two-app test relies on.
	_ = pc.SetMulticastLoopback(true)
	return &socketLink{pc: pc, dst: group}, nil
}

const mdnsGroupIP = "224.0.0.251"

type socketLink struct {
	pc  *ipv4.PacketConn
	dst *net.UDPAddr
}

func (s *socketLink) Send(b []byte) error {
	_, err := s.pc.WriteTo(b, nil, s.dst)
	return err
}

func (s *socketLink) Receive(b []byte) (int, error) {
	n, _, _, err := s.pc.ReadFrom(b)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return 0, errTimeout
		}
		return 0, err
	}
	return n, nil
}

func (s *socketLink) SetReadDeadline(t time.Time) error { return s.pc.SetReadDeadline(t) }

func (s *socketLink) Close() error { return s.pc.Close() }
