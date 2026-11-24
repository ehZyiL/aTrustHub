package discovery

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// clock is a manual clock so TTL behaviour is deterministic.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock {
	return &clock{t: time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)}
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// recordsFor builds the four records of one share as a responder would send
// them, with the given TTLs derived from the package defaults.
func recordsFor(ann Announcement, iface string) []Record {
	instance := InstanceName(ann.ShareID)
	host := HostLabel(ann.ShareID)
	hostTTL := uint32(TTLHost.Seconds())
	otherTTL := uint32(TTLOther.Seconds())
	return []Record{
		{Kind: KindPTR, Instance: instance, TTL: otherTTL, Interface: iface},
		{Kind: KindSRV, Instance: instance, Host: host, Port: ann.Port, TTL: hostTTL, Interface: iface},
		{Kind: KindTXT, Instance: instance, TXT: BuildTXT(ann), TTL: otherTTL, Interface: iface},
		{Kind: KindA, Host: host, IPv4: ann.Address, TTL: hostTTL, Interface: iface},
	}
}

func goodbyeFor(ann Announcement, iface string) []Record {
	instance := InstanceName(ann.ShareID)
	host := HostLabel(ann.ShareID)
	return []Record{
		{Kind: KindPTR, Instance: instance, Interface: iface},
		{Kind: KindSRV, Instance: instance, Host: host, Port: ann.Port, Interface: iface},
		{Kind: KindTXT, Instance: instance, TXT: BuildTXT(ann), Interface: iface},
		{Kind: KindA, Host: host, IPv4: ann.Address, Interface: iface},
	}
}

func applyAll(c *cache, records []Record) []Event {
	var events []Event
	for _, rec := range records {
		events = append(events, c.apply(rec)...)
	}
	return events
}

func TestCandidateNeedsEveryRecord(t *testing.T) {
	clk := newClock()
	c := newCache(clk.now)
	ann := testAnnouncement(1, "会议室共享")
	records := recordsFor(ann, "en0")

	if ev := applyAll(c, records[:2]); len(ev) != 0 {
		t.Fatalf("PTR+SRV 就形成了候选：%+v", ev)
	}
	if ev := applyAll(c, records[2:3]); len(ev) != 0 {
		t.Fatalf("缺 A 记录就形成了候选：%+v", ev)
	}
	ev := applyAll(c, records[3:])
	if len(ev) != 1 || ev[0].Kind != EventAdded {
		t.Fatalf("想要一次 added，得到 %+v", ev)
	}
	got := ev[0].Candidate
	if got.ShareID != ann.ShareID || got.Name != ann.Name || got.Address != ann.Address ||
		got.Port != ann.Port || got.Interface != "en0" {
		t.Fatalf("候选字段不对：%+v", got)
	}
	// A repeat announcement must not produce a second entry or flicker.
	if ev := applyAll(c, recordsFor(ann, "en0")); len(ev) != 0 {
		t.Fatalf("重复公告产生了变化：%+v", ev)
	}
	if n := len(c.snapshot()); n != 1 {
		t.Fatalf("候选数 = %d，want 1", n)
	}
}

func TestCandidateGoesAwayOnGoodbyeAndExpiry(t *testing.T) {
	ann := testAnnouncement(1, "开发机共享")
	for _, tc := range []struct {
		name   string
		remove func(*cache, *clock, Announcement)
	}{
		{"goodbye", func(c *cache, _ *clock, a Announcement) {
			if events := applyAll(c, goodbyeFor(a, "en0")); len(events) == 0 {
				t.Fatal("goodbye 没有产生移除事件")
			}
		}},
		{"ttl", func(c *cache, clk *clock, _ Announcement) { clk.advance(TTLOther + time.Second) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clk := newClock()
			c := newCache(clk.now)
			applyAll(c, recordsFor(ann, "en0"))
			if len(c.snapshot()) != 1 {
				t.Fatal("前置条件：候选应当存在")
			}
			tc.remove(c, clk, ann)
			if events := c.expire(); tc.name == "ttl" && len(events) == 0 {
				t.Fatalf("TTL 到期没有产生移除事件：%+v", events)
			}
			if n := len(c.snapshot()); n != 0 {
				t.Fatalf("候选没有被移除：%d", n)
			}
		})
	}
}

func TestAddressForAnotherHostIsIgnored(t *testing.T) {
	clk := newClock()
	c := newCache(clk.now)
	ann := testAnnouncement(1, "共享")
	records := recordsFor(ann, "en0")
	applyAll(c, records[:3])
	// An A record for the same instance but a different host name: this is how
	// an attacker would try to point a victim at another machine.
	grafted := Record{Kind: KindA, Host: "evil.local.", IPv4: "192.168.31.99",
		TTL: uint32(TTLHost.Seconds()), Interface: "en0"}
	if ev := c.apply(grafted); len(ev) != 0 {
		t.Fatalf("外来主机地址被接受：%+v", ev)
	}
	if n := len(c.snapshot()); n != 0 {
		t.Fatalf("凭证不完整的候选出现了：%d", n)
	}
	c.apply(records[3])
	cands := c.snapshot()
	if len(cands) != 1 || cands[0].Address != ann.Address {
		t.Fatalf("候选地址不对：%+v", cands)
	}
}

func TestCacheBoundsUnderAFlood(t *testing.T) {
	clk := newClock()
	c := newCache(clk.now)
	real := testAnnouncement(1, "真实分享")
	applyAll(c, recordsFor(real, "en0"))

	// 300 genuinely different instances: the old generator repeated every 64
	// IDs, so this test never actually reached the cap.
	for i := 0; i < MaxCandidates*2+44; i++ {
		sid := uniqueShareID(i)
		flood := testAnnouncement(1, "刷屏 "+sid)
		flood.ShareID = sid
		flood.Address = "192.168." + itoa(i/250+1) + "." + itoa(i%250+1)
		applyAll(c, recordsFor(flood, "en0"))
	}
	cands := c.snapshot()
	if len(cands) != MaxCandidates {
		t.Fatalf("候选数 = %d，want %d（上限必须正好守住）", len(cands), MaxCandidates)
	}
	found := false
	for _, cand := range cands {
		if cand.ShareID == real.ShareID {
			found = true
		}
	}
	if !found {
		t.Fatal("洪泛把真实条目挤掉了")
	}
}

// R1: a flood of PTR-only names must not grow the incomplete state either.
func TestPartialPTRFloodIsBounded(t *testing.T) {
	clk := newClock()
	c := newCache(clk.now)
	for i := 0; i < 4096; i++ {
		c.apply(Record{
			Kind: KindPTR, Instance: InstanceName(uniqueShareID(i)),
			TTL: uint32(TTLOther.Seconds()), Interface: "en0",
		})
	}
	// Compared against the specification limit, not against the implementation
	// constant: raising the constant must not make this test pass.
	if got := len(c.entries); got > MaxCandidates {
		t.Fatalf("未完成实例 %d 个，超过规格上限 %d", got, MaxCandidates)
	}
	if got := len(c.snapshot()); got != 0 {
		t.Fatalf("只有 PTR 却产生了 %d 个候选", got)
	}
}

// R1: address records for distinct owner names create one bucket each; that is
// state a sender controls too.
func TestUniqueAddressOwnerFloodIsBounded(t *testing.T) {
	clk := newClock()
	c := newCache(clk.now)
	for i := 0; i < 4096; i++ {
		c.apply(Record{
			Kind: KindA, Host: "ch-" + itoa(i) + ".local.",
			IPv4: "192.168.31." + itoa(i%250+2),
			TTL:  uint32(TTLHost.Seconds()), Interface: "en0",
		})
	}
	if got := len(c.hosts); got > MaxCandidates {
		t.Fatalf("地址宿主桶 %d 个，超过规格上限 %d", got, MaxCandidates)
	}
	if got := len(c.snapshot()); got != 0 {
		t.Fatalf("孤立地址产生了 %d 个候选", got)
	}
}

// R1: completing instances beyond the cap must not evict known candidates.
func TestCompletingBeyondTheCapKeepsTheCap(t *testing.T) {
	clk := newClock()
	c := newCache(clk.now)
	first := uniqueShareID(0)
	for i := 0; i < MaxCandidates; i++ {
		ann := testAnnouncement(1, "分享 "+itoa(i))
		ann.ShareID = uniqueShareID(i)
		applyAll(c, recordsFor(ann, "en0"))
	}
	// One more completes now: the list stays full and keeps the first entry.
	extra := testAnnouncement(1, "多余")
	extra.ShareID = uniqueShareID(MaxCandidates + 1)
	applyAll(c, recordsFor(extra, "en0"))
	cands := c.snapshot()
	if len(cands) != MaxCandidates {
		t.Fatalf("候选数 = %d，want %d", len(cands), MaxCandidates)
	}
	found := false
	for _, cand := range cands {
		if cand.ShareID == first {
			found = true
		}
	}
	if !found {
		t.Fatal("上限之外的完成把已知条目挤掉了")
	}
}

// R1: a partially assembled instance that never completes is dropped instead of
// being kept for the PTR TTL.
func TestPartialInstancesExpire(t *testing.T) {
	oldTTL := partialTTL
	partialTTL = 50 * time.Millisecond
	defer func() { partialTTL = oldTTL }()

	clk := newClock()
	c := newCache(clk.now)
	c.apply(Record{Kind: KindPTR, Instance: InstanceName(uniqueShareID(7)),
		TTL: uint32(TTLOther.Seconds()), Interface: "en0"})
	if len(c.entries) != 1 {
		t.Fatal("前置条件：应当留下一个未完成实例")
	}
	clk.advance(partialTTL + time.Second)
	c.expire()
	if len(c.entries) != 0 {
		t.Fatalf("未完成实例没有被回收：%d", len(c.entries))
	}
}

func TestAddressesPerInstanceAreBounded(t *testing.T) {
	clk := newClock()
	c := newCache(clk.now)
	ann := testAnnouncement(1, "共享")
	applyAll(c, recordsFor(ann, "en0"))
	host := HostLabel(ann.ShareID)
	for i := 0; i < 32; i++ {
		c.apply(Record{Kind: KindA, Host: host, IPv4: "192.168.31." + itoa(i+2),
			TTL: uint32(TTLHost.Seconds()), Interface: "en0"})
	}
	addrs := c.hosts[hostKey("en0", host)]
	if len(addrs) > MaxAddressesPerInstance {
		t.Fatalf("每实例地址数无界：%d", len(addrs))
	}
	if len(addrs) == 0 {
		t.Fatal("合法地址被拒绝")
	}
}

func TestCandidateMovesWhenThePortChanges(t *testing.T) {
	clk := newClock()
	c := newCache(clk.now)
	ann := testAnnouncement(1, "共享")
	applyAll(c, recordsFor(ann, "en0"))
	moved := ann
	moved.Port = ann.Port + 1
	events := applyAll(c, recordsFor(moved, "en0"))
	var removed, added int
	for _, ev := range events {
		switch ev.Kind {
		case EventRemoved:
			removed++
		case EventAdded:
			added++
		}
	}
	if removed != 1 || added != 1 {
		t.Fatalf("端口变化应当是一次移除加一次新增，得到 %+v", events)
	}
}

func TestTXTValidation(t *testing.T) {
	valid := BuildTXT(testAnnouncement(1, "共享"))
	cases := []struct {
		name  string
		parts []string
		ok    bool
	}{
		{"完整", valid, true},
		{"未知键被忽略", append(append([]string{}, valid...), "x=1", "y=2"), true},
		{"重复键", append(append([]string{}, valid...), "dv=1"), false},
		{"缺 sid", []string{"dv=1", "pv=1"}, false},
		{"坏 sid", []string{"dv=1", "pv=1", "sid=short"}, false},
		{"坏 dv", []string{"dv=xx", "pv=1", "sid=" + valid[2][4:]}, false},
		{"控制字符名称", []string{"dv=1", "pv=1", "sid=" + valid[2][4:], "name=bad\x00name"}, false},
		{"名称超长", []string{"dv=1", "pv=1", "sid=" + valid[2][4:], "name=" + strings.Repeat("长", 41)}, false},
		{"字段过多", manyFields(17), false},
		{"记录过大", manyFields(16, strings.Repeat("a", 60)), false},
		{"空值键", []string{"dv=", "pv=1", "sid=" + valid[2][4:]}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseTXT(tc.parts)
			if tc.ok && err != nil {
				t.Fatalf("应当接受：%v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("应当拒绝")
			}
		})
	}
}

func manyFields(n int, extra ...string) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, "k"+itoa(i)+"=v")
	}
	return append(out, extra...)
}

// uniqueShareID builds a distinct, well-formed 22 character share ID for i.
// Only digits are used so that two IDs never differ merely by case: DNS
// instance names are case-insensitive, and a case-only difference would collapse
// into one cache entry.
func uniqueShareID(i int) string {
	out := make([]byte, 22)
	for j := range out {
		out[j] = 'A'
	}
	for j := 21; j >= 0; j-- {
		out[j] = byte('0' + i%10)
		i /= 10
		if i == 0 {
			break
		}
	}
	return string(out)
}

func fakeShareID(i int) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	out := make([]byte, 22)
	for j := 0; j < 22; j++ {
		out[j] = alphabet[(i*7+j*13)%len(alphabet)]
	}
	return string(out)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// ---- publisher -----------------------------------------------------------

func TestPublisherPublishesThenWithdraws(t *testing.T) {
	hub := newHub()
	backend := newHubBackend(hub)
	statuses := make(chan Status, 8)
	pub := NewPublisher(PublisherOptions{
		Backend:  backend,
		OnChange: func(s Status) { statuses <- s },
	})
	defer pub.Close(context.Background())

	pub.Set(testAnnouncement(1, "共享"))
	waitFor(t, "published", func() bool { return pub.Status().State == StatusPublished })

	pub.Clear()
	waitFor(t, "idle", func() bool { return pub.Status().State == StatusIdle })
	if n := backend.closedCount(); n != 1 {
		t.Fatalf("撤销次数 = %d，want 1", n)
	}
}

func TestPublisherDropsALateRegistration(t *testing.T) {
	hub := newHub()
	backend := newHubBackend(hub)
	gate := make(chan struct{})
	backend.gate = gate
	pub := NewPublisher(PublisherOptions{Backend: backend})
	defer pub.Close(context.Background())

	// First announcement is being registered when the share closes.
	pub.Set(testAnnouncement(1, "第一次"))
	waitFor(t, "attempt started", func() bool { return len(backend.started) > 0 })
	pub.Clear()
	close(gate)
	waitFor(t, "idle", func() bool { return pub.Status().State == StatusIdle })
	pub.Set(testAnnouncement(2, "第二次"))
	waitFor(t, "published", func() bool { return pub.Status().State == StatusPublished })

	if got := pub.Status().Generation; got != 2 {
		t.Fatalf("发布的是第 %d 代，want 2", got)
	}
	// The first registration did complete after the share closed; it must have
	// been withdrawn immediately rather than published.
	backend.mu.Lock()
	closed := append([]Announcement(nil), backend.closed...)
	backend.mu.Unlock()
	if len(closed) != 1 || closed[0].Generation != 1 {
		t.Fatalf("迟到注册没有被撤销：%+v", closed)
	}
}

func TestPublisherRetriesAndStopsWhenCleared(t *testing.T) {
	hub := newHub()
	backend := newHubBackend(hub)
	backend.failures = 2
	pub := NewPublisher(PublisherOptions{
		Backend: backend,
		Retry:   []time.Duration{5 * time.Millisecond, 10 * time.Millisecond},
	})
	defer pub.Close(context.Background())

	pub.Set(testAnnouncement(1, "共享"))
	waitFor(t, "recovered", func() bool { return pub.Status().State == StatusPublished })
	if backend.attempts() < 3 {
		t.Fatalf("重试次数 = %d，want >= 3", backend.attempts())
	}

	backend.mu.Lock()
	backend.failures = 1000
	backend.mu.Unlock()
	pub.Set(testAnnouncement(2, "共享"))
	waitFor(t, "failed", func() bool { return pub.Status().State == StatusFailed })
	pub.Clear()
	waitFor(t, "idle", func() bool { return pub.Status().State == StatusIdle })
	before := backend.attempts()
	time.Sleep(40 * time.Millisecond)
	if after := backend.attempts(); after > before {
		t.Fatalf("撤销后仍在重试：%d -> %d", before, after)
	}
}

// ---- browser -------------------------------------------------------------

func TestBrowserDropsAnOlderGeneration(t *testing.T) {
	hub := newHub()
	backend := &captureBackend{hub: hub}
	snapshots := make(chan Snapshot, 16)
	b := NewBrowser(BrowserOptions{Backend: backend, Emit: func(s Snapshot) {
		select {
		case snapshots <- s:
		default:
		}
	}})
	defer b.Close()

	if err := b.Start([]Interface{testInterface("en0")}); err != nil {
		t.Fatal(err)
	}
	_ = backend.last()
	startedBefore := backend.count()
	if err := b.Start([]Interface{testInterface("en1")}); err != nil {
		t.Fatal(err)
	}
	if backend.count() != startedBefore+1 {
		t.Fatal("第二次开始浏览没有建立新的会话")
	}
	first := backend.at(startedBefore)
	if err := b.Refresh(); err != nil {
		t.Fatal(err)
	}
	ann := testAnnouncement(1, "共享")
	// A record arriving through the *old* session must not enter the new list.
	first([]Record{{Kind: KindPTR, Instance: InstanceName(ann.ShareID), TTL: 4500, Interface: "en0"}})
	if got := len(b.Snapshot().Candidates); got != 0 {
		t.Fatalf("旧代次的记录进入了新列表：%d", got)
	}
	backend.last()(recordsFor(ann, "en1"))
	if got := len(b.Snapshot().Candidates); got != 1 {
		t.Fatalf("新代次的记录没有进入列表：%d", got)
	}
}

func TestBrowserStopsEmittingAfterClose(t *testing.T) {
	hub := newHub()
	backend := &captureBackend{hub: hub}
	var mu sync.Mutex
	emits := 0
	b := NewBrowser(BrowserOptions{Backend: backend, Emit: func(Snapshot) {
		mu.Lock()
		emits++
		mu.Unlock()
	}})
	if err := b.Start([]Interface{testInterface("en0")}); err != nil {
		t.Fatal(err)
	}
	onRecords := backend.last()
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	before := emits
	mu.Unlock()
	onRecords(recordsFor(testAnnouncement(1, "共享"), "en0"))
	time.Sleep(30 * time.Millisecond)
	mu.Lock()
	after := emits
	mu.Unlock()
	if after != before {
		t.Fatalf("关闭后仍在推送快照：%d -> %d", before, after)
	}
}

func TestBrowserWithoutInterfacesReportsWhy(t *testing.T) {
	b := NewBrowser(BrowserOptions{Backend: &captureBackend{hub: newHub()}})
	defer b.Close()
	if err := b.Start(nil); err == nil {
		t.Fatal("没有网卡时应当报错")
	}
	if b.Err() == "" {
		t.Fatal("应当说明原因")
	}
}

// captureBackend records the OnRecords callback of every browsing session so a
// test can inject records without a real socket.
type captureBackend struct {
	hub *hub
	mu  sync.Mutex
	cb  []func([]Record)
}

func (c *captureBackend) Advertise(ctx context.Context, a Announcement) (Registration, error) {
	base := &mdnsBackend{open: c.hub.open, logf: func(string, ...any) {}, now: time.Now}
	return base.Advertise(ctx, a)
}

func (c *captureBackend) Browse(ctx context.Context, opts BrowseOptions) (Session, error) {
	c.mu.Lock()
	c.cb = append(c.cb, opts.OnRecords)
	c.mu.Unlock()
	return nopSession{}, nil
}

func (c *captureBackend) at(i int) func([]Record) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cb[i]
}

func (c *captureBackend) last() func([]Record) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cb[len(c.cb)-1]
}

func (c *captureBackend) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.cb)
}

type nopSession struct{}

func (nopSession) Refresh() error { return nil }
func (nopSession) Close() error   { return nil }

// ---- end to end through the hub ------------------------------------------

func TestHubPublishToBrowserEndToEnd(t *testing.T) {
	hub := newHub()
	aBackend := newHubBackend(hub)
	bBackend := newHubBackend(hub)

	pub := NewPublisher(PublisherOptions{Backend: aBackend})
	defer pub.Close(context.Background())
	snapshots := make(chan Snapshot, 32)
	b := NewBrowser(BrowserOptions{Backend: bBackend, Emit: func(s Snapshot) {
		select {
		case snapshots <- s:
		default:
		}
	}})
	defer b.Close()

	if err := b.Start([]Interface{testInterface("en0")}); err != nil {
		t.Fatal(err)
	}
	pub.Set(testAnnouncement(1, "会议室共享"))
	waitFor(t, "candidate appeared", func() bool { return len(b.Snapshot().Candidates) == 1 })
	cand := b.Snapshot().Candidates[0]
	if cand.Name != "会议室共享" || cand.Port != 23456 || cand.Address != "192.168.31.61" {
		t.Fatalf("候选不对：%+v", cand)
	}
	if !cand.Compatible() {
		t.Fatal("同版本应当兼容")
	}

	// The share stops: the goodbye removes it without waiting for the TTL.
	pub.Clear()
	waitFor(t, "candidate removed", func() bool { return len(b.Snapshot().Candidates) == 0 })
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("等待超时：%s", what)
}

var _ = errors.New

// C18: a record the feature cannot use is refused with a clear outcome instead
// of producing a half-usable candidate.
func TestUnusableRecordsAreRefused(t *testing.T) {
	cat := func(kind RecordKind, mutate func(*Record)) []Event {
		clk := newClock()
		c := newCache(clk.now)
		ann := testAnnouncement(1, "共享")
		records := recordsFor(ann, "en0")
		applyAll(c, records[:3])
		rec := records[3]
		rec.Kind = kind
		if mutate != nil {
			mutate(&rec)
		}
		return c.apply(rec)
	}
	for _, tc := range []struct {
		name   string
		kind   RecordKind
		mutate func(*Record)
	}{
		{"公网地址", KindA, func(r *Record) { r.IPv4 = "8.8.8.8" }},
		{"IPv6", KindA, func(r *Record) { r.IPv4 = "fe80::1" }},
		{"坏地址", KindA, func(r *Record) { r.IPv4 = "not-an-ip" }},
		{"端口为 0", KindSRV, func(r *Record) { r.Port = 0 }},
		{"端口越界", KindSRV, func(r *Record) { r.Port = 70000 }},
		{"坏 dv", KindTXT, func(r *Record) { r.TXT = []string{"dv=2", "pv=1", "sid=AAAAAAAAAAAAAAAAAAAAAA"} }},
		{"缺 sid", KindTXT, func(r *Record) { r.TXT = []string{"dv=1", "pv=1"} }},
		{"非 UTF-8 名称", KindTXT, func(r *Record) {
			r.TXT = []string{"dv=1", "pv=1", "sid=AAAAAAAAAAAAAAAAAAAAAA", "name=\xff\xfe"}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if ev := cat(tc.kind, tc.mutate); len(ev) != 0 {
				t.Fatalf("不可用的记录产生了候选：%+v", ev)
			}
		})
	}
}

// C17: the same instance seen on two interfaces stays two entries, and a second
// endpoint for one instance cannot create a duplicate or an unstable address.
func TestSameInstanceOnTwoInterfaces(t *testing.T) {
	clk := newClock()
	c := newCache(clk.now)
	ann := testAnnouncement(1, "共享")
	applyAll(c, recordsFor(ann, "en0"))
	applyAll(c, recordsFor(ann, "en1"))
	if n := len(c.snapshot()); n != 2 {
		t.Fatalf("多网卡同一实例应当分别保留，得到 %d", n)
	}

	// A second address record for the same host on one interface is kept
	// bounded, and the chosen address is deterministic.
	host := HostLabel(ann.ShareID)
	for _, ip := range []string{"192.168.31.62", "192.168.31.63"} {
		c.apply(Record{Kind: KindA, Host: host, IPv4: ip,
			TTL: uint32(TTLHost.Seconds()), Interface: "en0"})
	}
	cands := c.snapshot()
	if len(cands) != 2 {
		t.Fatalf("同一个实例被拆成了 %d 条", len(cands))
	}
	for _, cand := range cands {
		if cand.Interface == "en0" && cand.Address != "192.168.31.61" {
			t.Fatalf("地址选择不稳定：%s", cand.Address)
		}
	}
}

// B13: a rename while the previous registration is still in flight must end on
// the newest announcement, with the old one withdrawn.
func TestPublisherRenameDuringRegistration(t *testing.T) {
	hub := newHub()
	backend := newHubBackend(hub)
	backend.blocker = make(chan struct{})
	pub := NewPublisher(PublisherOptions{Backend: backend})
	defer pub.Close(context.Background())

	pub.Set(testAnnouncement(1, "旧名字"))
	waitFor(t, "attempt", func() bool { return len(backend.started) > 0 })
	renamed := testAnnouncement(1, "新名字")
	pub.Set(renamed)
	close(backend.blocker)
	waitFor(t, "published", func() bool { return pub.Status().State == StatusPublished })
	anns := backend.announcements()
	if len(anns) == 0 || anns[len(anns)-1].Name != "新名字" {
		t.Fatalf("最终发布的不是新名字：%+v", anns)
	}
	if got := backend.liveCount(); got != 1 {
		t.Fatalf("同时存在 %d 条公告", got)
	}
}

// stuckBackend ignores cancellation, like a platform call that never returns.
type stuckBackend struct {
	release chan struct{}
}

func (b *stuckBackend) Advertise(context.Context, Announcement) (Registration, error) {
	<-b.release
	return nopReg{}, nil
}

func (b *stuckBackend) Browse(context.Context, BrowseOptions) (Session, error) {
	return nopSession{}, nil
}

type nopReg struct{}

func (nopReg) Close() error { return nil }

// B15: quitting within budget never hangs, even when the platform call cannot be
// cancelled. The withdrawal is reported as unfinished instead of blocking exit.
func TestPublisherCloseRespectsItsBudget(t *testing.T) {
	backend := &stuckBackend{release: make(chan struct{})}
	defer close(backend.release)
	pub := NewPublisher(PublisherOptions{Backend: backend})
	pub.Set(testAnnouncement(1, "共享"))
	waitFor(t, "attempt", func() bool { return pub.Status().State == StatusPending })
	time.Sleep(20 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := pub.Close(ctx)
	if err == nil {
		t.Fatal("后端起不来时应当报告预算耗尽")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("退出等待了 %v", elapsed)
	}
}

// C19/C20: browsing can be started and closed repeatedly without leaking
// goroutines, and closing completes even while packets are still arriving.
func TestBrowserCyclesDoNotLeak(t *testing.T) {
	hub := newHub()
	backend := newHubBackend(hub)
	b := NewBrowser(BrowserOptions{Backend: backend, Emit: func(Snapshot) {}})
	defer b.Close()

	baseline := runtime.NumGoroutine()
	for i := 0; i < 100; i++ {
		if err := b.Start([]Interface{testInterface("en0")}); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && runtime.NumGoroutine() > baseline+8 {
		time.Sleep(10 * time.Millisecond)
	}
	if got := runtime.NumGoroutine(); got > baseline+8 {
		t.Fatalf("100 次开关后 goroutine 从 %d 涨到 %d", baseline, got)
	}
}

// C19: a slow consumer must not be able to block the receive loop or the close.
func TestBrowserCloseWithPacketsInFlight(t *testing.T) {
	hub := newHub()
	backend := newHubBackend(hub)
	done := make(chan struct{})
	b := NewBrowser(BrowserOptions{Backend: backend, Emit: func(Snapshot) {
		select {
		case <-done:
		default:
		}
	}})
	if err := b.Start([]Interface{testInterface("en0")}); err != nil {
		t.Fatal(err)
	}
	ann := testAnnouncement(1, "共享")
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			backend.hub.mu.Lock()
			links := append([]*hubLink(nil), backend.hub.links...)
			backend.hub.mu.Unlock()
			for _, l := range links {
				select {
				case l.ch <- []byte("noise"):
				default:
				}
			}
		}
	}()
	time.Sleep(10 * time.Millisecond)
	closed := make(chan error, 1)
	go func() { closed <- b.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("关闭浏览被慢消费者卡住")
	}
	close(stop)
	close(done)
	_ = ann
}

// Review: closing the page closed the browser for good, so reopening the dialog
// never discovered anything again. Start must reopen a closed browser.
func TestBrowserReopensAfterClose(t *testing.T) {
	hub := newHub()
	backend := newHubBackend(hub)
	b := NewBrowser(BrowserOptions{Backend: backend, Emit: func(Snapshot) {}})
	defer b.Close()
	if err := b.Start([]Interface{testInterface("en0")}); err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if err := b.Start([]Interface{testInterface("en0")}); err != nil {
		t.Fatalf("重新打开浏览失败：%v", err)
	}
	ann := testAnnouncement(1, "共享")
	// A real announcement travels through the hub, so this also proves the
	// session was actually rebuilt.
	reg, err := backend.Advertise(context.Background(), ann)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()
	waitFor(t, "candidate after reopen", func() bool { return len(b.Snapshot().Candidates) == 1 })
}

// Review: every received PTR triggered an extra SRV/TXT query, so a forged
// flood made this host send one packet per packet received. Each instance is
// queried once per session.
func TestRepeatedPTRIsQueriedOnce(t *testing.T) {
	hub := newHub()
	var mu sync.Mutex
	var browserLink *hubLink
	backend := &recordBackend{hub: hub, onOpen: func(l *hubLink) {
		mu.Lock()
		browserLink = l
		mu.Unlock()
	}}
	b := NewBrowser(BrowserOptions{Backend: backend, Emit: func(Snapshot) {}})
	defer b.Close()
	if err := b.Start([]Interface{testInterface("en0")}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	l := browserLink
	mu.Unlock()
	if l == nil {
		t.Fatal("没有建立浏览链路")
	}
	// A peer on the same in-memory link sends the same PTR response repeatedly,
	// which is exactly what a forged flood looks like on the wire.
	peer, err := hub.open(testInterface("en0"))
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	ann := testAnnouncement(1, "共享")
	packed, err := announcementMessage(ann, false).Pack()
	if err != nil {
		t.Fatal(err)
	}
	before := l.sentCount()
	for i := 0; i < 50; i++ {
		if err := peer.Send(packed); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && l.sentCount()-before < 1 {
		time.Sleep(5 * time.Millisecond)
	}
	if got := l.sentCount() - before; got > 3 {
		t.Fatalf("重复 PTR 触发了 %d 个报文", got)
	}
}

// recordBackend hands the test the link it opens.
type recordBackend struct {
	hub    *hub
	onOpen func(*hubLink)
	mu     sync.Mutex
	recs   func([]Record)
}

func (b *recordBackend) Advertise(ctx context.Context, a Announcement) (Registration, error) {
	base := &mdnsBackend{open: b.hub.open, logf: func(string, ...any) {}, now: time.Now}
	return base.Advertise(ctx, a)
}

func (b *recordBackend) Browse(ctx context.Context, opts BrowseOptions) (Session, error) {
	b.mu.Lock()
	b.recs = opts.OnRecords
	b.mu.Unlock()
	base := &mdnsBackend{open: func(ifi Interface) (link, error) {
		l, err := b.hub.open(ifi)
		if err == nil && b.onOpen != nil {
			b.onOpen(l.(*hubLink))
		}
		return l, err
	}, logf: func(string, ...any) {}, now: time.Now}
	return base.Browse(ctx, opts)
}

func (b *recordBackend) feed(records []Record) {
	b.mu.Lock()
	fn := b.recs
	b.mu.Unlock()
	if fn != nil {
		fn(records)
	}
}

// Review: the expiry ticker could push one more snapshot after Close (it runs
// its own goroutine), so the closed browser must refuse to publish.
func TestBrowserDoesNotEmitAfterClose(t *testing.T) {
	hub := newHub()
	backend := newHubBackend(hub)
	var mu sync.Mutex
	emits := 0
	b := NewBrowser(BrowserOptions{Backend: backend, Emit: func(Snapshot) {
		mu.Lock()
		emits++
		mu.Unlock()
	}})
	if err := b.Start([]Interface{testInterface("en0")}); err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	before := emits
	mu.Unlock()
	// The ticker and any late callback both end here.
	b.publish()
	b.apply(1, recordsFor(testAnnouncement(1, "共享"), "en0"))
	time.Sleep(20 * time.Millisecond)
	mu.Lock()
	after := emits
	mu.Unlock()
	if after != before {
		t.Fatalf("关闭后仍推送了 %d 次快照", after-before)
	}
}

// A backend that returns no registration must not look published.
type nilRegBackend struct{}

func (nilRegBackend) Advertise(context.Context, Announcement) (Registration, error) {
	return nil, nil
}
func (nilRegBackend) Browse(context.Context, BrowseOptions) (Session, error) {
	return nopSession{}, nil
}

func TestPublisherRejectsANilRegistration(t *testing.T) {
	pub := NewPublisher(PublisherOptions{
		Backend: nilRegBackend{},
		Retry:   []time.Duration{time.Hour},
	})
	defer pub.Close(context.Background())
	pub.Set(testAnnouncement(1, "共享"))
	waitFor(t, "failed", func() bool { return pub.Status().State == StatusFailed })
	if !strings.Contains(pub.Status().Message, "注册句柄") {
		t.Fatalf("状态信息不明确：%q", pub.Status().Message)
	}
}

// Spec §5.2: an announcement reflected from another subnet is not a share the
// user can reach on the interface they picked.
func TestOnLinkOnlyAcceptsTheInterfacesSubnet(t *testing.T) {
	iface := Interface{Name: "en0", IPv4: "192.168.31.61", Subnet: "192.168.31.0/24"}
	for _, tc := range []struct {
		ip string
		ok bool
	}{
		{"192.168.31.62", true},
		{"192.168.31.61", true},
		{"192.168.99.5", false},
		{"10.0.0.5", false},
		{"8.8.8.8", false},
		{"not-an-ip", false},
	} {
		if got := iface.OnLink(tc.ip); got != tc.ok {
			t.Fatalf("OnLink(%q) = %v, want %v", tc.ip, got, tc.ok)
		}
	}
	// An interface without a subnet keeps the old behaviour: no extra check.
	plain := Interface{Name: "en0", IPv4: "192.168.31.61"}
	if !plain.OnLink("10.1.2.3") {
		t.Fatal("没有子网信息时不应拒绝")
	}
	// A malformed subnet fails closed rather than accepting everything.
	broken := Interface{Name: "en0", Subnet: "nonsense"}
	if broken.OnLink("192.168.31.62") {
		t.Fatal("子网信息损坏时应当拒绝")
	}
}

// The browser applies the same check with the interface it was given, so a
// record that arrives on en0 pointing at another subnet never becomes a row.
func TestBrowserDropsOffLinkRecords(t *testing.T) {
	hub := newHub()
	backend := &captureBackend{hub: hub}
	b := NewBrowser(BrowserOptions{Backend: backend, Emit: func(Snapshot) {}})
	defer b.Close()
	iface := Interface{Name: "en0", IPv4: "192.168.31.61", Subnet: "192.168.31.0/24"}
	if err := b.Start([]Interface{iface}); err != nil {
		t.Fatal(err)
	}
	inject := backend.last()
	ann := testAnnouncement(1, "共享")
	records := recordsFor(ann, "en0")
	records[3].IPv4 = "192.168.99.5"
	inject(records)
	time.Sleep(20 * time.Millisecond)
	if got := len(b.Snapshot().Candidates); got != 0 {
		t.Fatalf("异网段公告进入了列表：%d", got)
	}
	records[3].IPv4 = "192.168.31.62"
	inject(records)
	waitFor(t, "on-link candidate", func() bool { return len(b.Snapshot().Candidates) == 1 })
}
