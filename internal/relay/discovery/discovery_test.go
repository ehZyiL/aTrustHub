package discovery

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// ---- in-memory multicast hub ---------------------------------------------
//
// The hub replaces the socket so protocol, cache and lifecycle tests are
// deterministic: packets travel between links of the same interface name, with
// no real multicast, no ports and no timing luck.

type hub struct {
	mu    sync.Mutex
	links []*hubLink
	// deliver lets a test drop packets on purpose (a lost goodbye, for
	// example) without touching the code under test.
	deliver func(from *hubLink) bool
}

func newHub() *hub { return &hub{} }

func (h *hub) open(ifi Interface) (link, error) {
	l := &hubLink{hub: h, ifi: ifi, ch: make(chan []byte, 256), closed: make(chan struct{})}
	h.mu.Lock()
	h.links = append(h.links, l)
	h.mu.Unlock()
	return l, nil
}

type hubLink struct {
	hub    *hub
	ifi    Interface
	ch     chan []byte
	closed chan struct{}
	once   sync.Once

	mu       sync.Mutex
	deadline time.Time
}

func (l *hubLink) Send(b []byte) error {
	select {
	case <-l.closed:
		return errors.New("closed")
	default:
	}
	h := l.hub
	h.mu.Lock()
	targets := append([]*hubLink(nil), h.links...)
	deliver := h.deliver
	h.mu.Unlock()
	if deliver != nil && !deliver(l) {
		return nil
	}
	payload := append([]byte(nil), b...)
	for _, t := range targets {
		if t == l || t.ifi.Name != l.ifi.Name {
			continue
		}
		select {
		case t.ch <- payload:
		default:
			// A slow consumer drops packets exactly like a real socket.
		}
	}
	return nil
}

func (l *hubLink) Receive(b []byte) (int, error) {
	l.mu.Lock()
	deadline := l.deadline
	l.mu.Unlock()
	var timer <-chan time.Time
	if !deadline.IsZero() {
		t := time.NewTimer(time.Until(deadline))
		defer t.Stop()
		timer = t.C
	}
	select {
	case <-l.closed:
		return 0, errors.New("closed")
	case pkt := <-l.ch:
		return copy(b, pkt), nil
	case <-timer:
		return 0, errTimeout
	}
}

func (l *hubLink) SetReadDeadline(t time.Time) error {
	l.mu.Lock()
	l.deadline = t
	l.mu.Unlock()
	return nil
}

func (l *hubLink) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

// hubBackend is a Backend over the in-memory hub.
type hubBackend struct {
	hub  *hub
	base *mdnsBackend
	// blockRegistration makes Advertise wait for the context, which is how the
	// late-registration tests create their window.
	blockRegistration bool
	// gate delays a registration so a test can close the share in between.
	gate chan struct{}
	// blocker makes Advertise wait until it is closed, without touching the
	// context, which lets a test supersede an attempt that is already running.
	blocker chan struct{}
	// failures makes the next N registrations fail, for the retry tests.
	failures  int
	attempted int
	started   chan Announcement
	created   []Announcement
	mu        sync.Mutex
	closed    []Announcement
}

func newHubBackend(h *hub) *hubBackend {
	b := &hubBackend{hub: h, started: make(chan Announcement, 16)}
	b.base = &mdnsBackend{open: h.open, logf: func(string, ...any) {}, now: time.Now}
	return b
}

func (b *hubBackend) Advertise(ctx context.Context, a Announcement) (Registration, error) {
	select {
	case b.started <- a:
	default:
	}
	if b.blockRegistration {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if b.gate != nil {
		select {
		case <-b.gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if b.blocker != nil {
		select {
		case <-b.blocker:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	b.mu.Lock()
	b.attempted++
	failing := b.failures > 0
	if failing {
		b.failures--
	}
	b.mu.Unlock()
	if failing {
		return nil, errors.New("模拟注册失败")
	}
	reg, err := b.base.Advertise(ctx, a)
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	b.created = append(b.created, a)
	b.mu.Unlock()
	return &countingReg{Registration: reg, backend: b, ann: a}, nil
}

func (b *hubBackend) Browse(ctx context.Context, opts BrowseOptions) (Session, error) {
	return b.base.Browse(ctx, opts)
}

type countingReg struct {
	Registration
	backend *hubBackend
	ann     Announcement
	once    sync.Once
}

func (r *countingReg) Close() error {
	err := r.Registration.Close()
	r.once.Do(func() {
		r.backend.mu.Lock()
		r.backend.closed = append(r.backend.closed, r.ann)
		r.backend.mu.Unlock()
	})
	return err
}

// announcements lists every registration that was actually created, in order.
func (b *hubBackend) announcements() []Announcement {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]Announcement(nil), b.created...)
}

// liveCount is how many registrations are currently published.
func (b *hubBackend) liveCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.created) - len(b.closed)
}

func (b *hubBackend) attempts() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.attempted
}

func (b *hubBackend) closedCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.closed)
}

func testInterface(name string) Interface {
	return Interface{Name: name, IPv4: "192.168.31.61"}
}

func testAnnouncement(gen uint64, name string) Announcement {
	return Announcement{
		Generation:      gen,
		ShareID:         "AAAAAAAAAAAAAAAAAAAAAA",
		Name:            name,
		ProtocolVersion: 1,
		Interface:       testInterface("en0"),
		Address:         "192.168.31.61",
		Port:            23456,
	}
}

// ---- wire ----------------------------------------------------------------

func TestWireRoundTrip(t *testing.T) {
	ann := testAnnouncement(1, "会议室共享")
	packed, err := announcementMessage(ann, false).Pack()
	if err != nil {
		t.Fatal(err)
	}
	var msg dns.Msg
	if err := msg.Unpack(packed); err != nil {
		t.Fatal(err)
	}
	records := parseRecords(&msg, "en0")
	kinds := map[RecordKind]Record{}
	for _, rec := range records {
		kinds[rec.Kind] = rec
	}
	if len(records) != 4 {
		t.Fatalf("要 4 条记录，得到 %d：%+v", len(records), records)
	}
	if ptr := kinds[KindPTR]; ptr.Instance != InstanceName(ann.ShareID) {
		t.Fatalf("PTR 实例名不对：%q", ptr.Instance)
	}
	if srv := kinds[KindSRV]; srv.Port != ann.Port || srv.Host != HostLabel(ann.ShareID) {
		t.Fatalf("SRV 不对：%+v", srv)
	}
	if txt := kinds[KindTXT]; len(txt.TXT) != 4 {
		t.Fatalf("TXT 字段数不对：%v", txt.TXT)
	}
	if a := kinds[KindA]; a.IPv4 != ann.Address || a.Host != HostLabel(ann.ShareID) {
		t.Fatalf("A 记录不对：%+v", a)
	}
	// RFC 6762 §10: host-bearing records use 120s, PTR/TXT the long default.
	if got := time.Duration(kinds[KindSRV].TTL) * time.Second; got != TTLHost {
		t.Fatalf("SRV TTL = %v，want %v", got, TTLHost)
	}
	if got := time.Duration(kinds[KindA].TTL) * time.Second; got != TTLHost {
		t.Fatalf("A TTL = %v，want %v", got, TTLHost)
	}
	if got := time.Duration(kinds[KindPTR].TTL) * time.Second; got != TTLOther {
		t.Fatalf("PTR TTL = %v，want %v", got, TTLOther)
	}
	if got := time.Duration(kinds[KindTXT].TTL) * time.Second; got != TTLOther {
		t.Fatalf("TXT TTL = %v，want %v", got, TTLOther)
	}

	goodbye, err := announcementMessage(ann, true).Pack()
	if err != nil {
		t.Fatal(err)
	}
	if err := msg.Unpack(goodbye); err != nil {
		t.Fatal(err)
	}
	for _, rec := range parseRecords(&msg, "en0") {
		if rec.TTL != 0 || !rec.Gone() {
			t.Fatalf("goodbye 记录 TTL 不是 0：%+v", rec)
		}
	}
}

func TestWireIgnoresForeignTraffic(t *testing.T) {
	// A response for another service type and another record type.
	m := &dns.Msg{Response: true}
	m.Answer = append(m.Answer, &dns.PTR{
		Hdr: dns.RR_Header{Name: "_ipp._tcp.local.", Rrtype: 12, Class: 1, Ttl: 120},
		Ptr: "printer._ipp._tcp.local.",
	})
	m.Answer = append(m.Answer, &dns.TXT{
		Hdr: dns.RR_Header{Name: "_ipp._tcp.local.", Rrtype: 16, Class: 1, Ttl: 120},
		Txt: []string{"ty=printer"},
	})
	if recs := parseRecords(m, "en0"); len(recs) != 0 {
		t.Fatalf("外来记录被接受：%+v", recs)
	}
	// A query is not a response and must be ignored.
	q := browseQuery()
	if recs := parseRecords(q, "en0"); len(recs) != 0 {
		t.Fatalf("查询被当成响应：%+v", recs)
	}
	// IPv6-only answers are ignored, not fatal.
	a := &dns.Msg{Response: true}
	a.Answer = append(a.Answer, &dns.AAAA{
		Hdr: dns.RR_Header{Name: HostLabel("AAAAAAAAAAAAAAAAAAAAAA"), Rrtype: 28, Class: 1, Ttl: 120},
	})
	if recs := parseRecords(a, "en0"); len(recs) != 0 {
		t.Fatalf("IPv6 记录被接受：%+v", recs)
	}
}

// A name longer than one DNS character-string is split by the wire format and
// must arrive intact: multicast DNS escapes non-ASCII bytes, so a Chinese name
// can span several strings.
func TestWireRoundTripsALongChineseName(t *testing.T) {
	name := strings.Repeat("会议室", 13) // 39 characters, 117 bytes
	ann := testAnnouncement(1, name)
	if err := ann.Validate(); err != nil {
		t.Fatalf("前置条件：名称应当合法：%v", err)
	}
	packed, err := announcementMessage(ann, false).Pack()
	if err != nil {
		t.Fatal(err)
	}
	var msg dns.Msg
	if err := msg.Unpack(packed); err != nil {
		t.Fatal(err)
	}
	var txtParts []string
	for _, rec := range parseRecords(&msg, "en0") {
		if rec.Kind == KindTXT {
			txtParts = rec.TXT
		}
	}
	if len(txtParts) < 2 {
		t.Fatalf("前置条件：名称应当被拆成多个字符串，实际 %d 个", len(txtParts))
	}
	fields, err := ParseTXT(txtParts)
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	if fields.Name != name {
		t.Fatalf("名称往返后变了：%q", fields.Name)
	}
}
