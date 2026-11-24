package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"

	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/ehzyil/connect-hub/internal/relay"
	"github.com/ehzyil/connect-hub/internal/relay/discovery"
	"github.com/ehzyil/connect-hub/internal/vpn"
)

// testDiscoveryBackend is the in-memory discovery platform used by the app
// tests. It records what the publisher asked for and lets a test feed records
// to the browser, so the 33 acceptance items can be exercised without a real
// multicast network.
type testDiscoveryBackend struct {
	mu        sync.Mutex
	anns      []discovery.Announcement
	live      map[int]bool
	nextID    int
	failWith  error
	blocker   chan struct{}
	browsed   [][]discovery.Interface
	records   func([]discovery.Record)
	browseErr error
	closed    int
}

func newTestDiscoveryBackend() *testDiscoveryBackend {
	return &testDiscoveryBackend{live: map[int]bool{}}
}

func (b *testDiscoveryBackend) Advertise(ctx context.Context, a discovery.Announcement) (discovery.Registration, error) {
	b.mu.Lock()
	if b.failWith != nil {
		err := b.failWith
		b.mu.Unlock()
		return nil, err
	}
	blocker := b.blocker
	b.mu.Unlock()
	if blocker != nil {
		select {
		case <-blocker:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	b.mu.Lock()
	b.nextID++
	id := b.nextID
	b.anns = append(b.anns, a)
	b.live[id] = true
	b.mu.Unlock()
	return &testRegistration{backend: b, id: id}, nil
}

type testRegistration struct {
	backend *testDiscoveryBackend
	id      int
	once    sync.Once
}

func (r *testRegistration) Close() error {
	r.once.Do(func() {
		r.backend.mu.Lock()
		r.backend.closed++
		delete(r.backend.live, r.id)
		r.backend.mu.Unlock()
	})
	return nil
}

func (b *testDiscoveryBackend) Browse(ctx context.Context, opts discovery.BrowseOptions) (discovery.Session, error) {
	b.mu.Lock()
	b.browsed = append(b.browsed, opts.Interfaces)
	b.records = opts.OnRecords
	err := b.browseErr
	b.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return testSession{ctx: ctx}, nil
}

type testSession struct{ ctx context.Context }

func (s testSession) Refresh() error { return nil }
func (s testSession) Close() error   { return nil }

func (b *testDiscoveryBackend) announcements() []discovery.Announcement {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]discovery.Announcement(nil), b.anns...)
}

func (b *testDiscoveryBackend) liveCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.live)
}

func (b *testDiscoveryBackend) feed(records []discovery.Record) {
	b.mu.Lock()
	fn := b.records
	b.mu.Unlock()
	if fn != nil {
		fn(records)
	}
}

// localLANAddress returns a real LAN address of this machine, or skips the test.
// A share that can be announced must bind an address that exists; inventing one
// would test a state the product never reaches.
func localLANAddress(t *testing.T) relay.Interface {
	t.Helper()
	for _, cand := range (lanAddresses{}).LANCandidates() {
		if cand.IPv4 != "" && !virtualInterface(cand.Name) {
			return cand
		}
	}
	t.Skip("没有可用的局域网地址，跳过依赖真实绑定地址的用例（需实机覆盖）")
	return relay.Interface{}
}

// discoveryApp builds an app with the LAN share controller and the discovery
// machine wired to the in-memory backend, exactly like the production wiring
// but without multicast sockets.
func discoveryApp(t *testing.T) (*app, *testDiscoveryBackend, relay.Interface) {
	t.Helper()
	a := testApp(t)
	backend := newTestDiscoveryBackend()
	a.discoveryBackend = backend
	iface := localLANAddress(t)
	if _, err := a.store.Update(func(cfg *model.Config) error {
		cfg.Add(model.AccessPoint{ID: "p1", Name: "公司 VPN", Protocol: model.ProtocolATrust,
			Server: "vpn.example.com", Port: 443, Username: "u", InPool: true})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	a.setConfig(a.store.Config())
	a.mgr.Apply(a.cfg)
	echo, closeEcho := echoListenerForTest(t)
	t.Cleanup(closeEcho)
	// The real address provider: a share that can be announced must bind an
	// address that exists on this machine.
	installLANShareWith(t, a, &appTestSink{names: map[string]string{"p1": "公司 VPN"}, echo: echo}, lanAddresses{})
	a.setupLANDiscovery()
	t.Cleanup(a.shutdownLANDiscovery)
	return a, backend, iface
}

// enableShare turns the share on with the given discovery choice and waits for
// the controller to reach Running, which is the only state that may announce.
func enableShare(t *testing.T, a *app, iface relay.Interface, discoveryOn bool, name string) {
	t.Helper()
	if err := a.lanShare.Enable(context.Background(), relay.EnableOptions{
		PointID:       "p1",
		InterfaceName: iface.Name,
		PreferredIPv4: iface.IPv4,
		Discovery:     discoveryOn,
		DiscoveryName: name,
	}); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	waitAppShare(t, a, relay.StateRunning)
}

// blockStoreSaves makes the next store write fail by replacing config.json with
// a non-empty directory, which an atomic rename cannot overwrite. It works
// without relying on file permissions, so it also holds when tests run as root.
func blockStoreSaves(t *testing.T, a *app) func() {
	t.Helper()
	path := filepath.Join(a.store.Dir(), "config.json")
	backup, readErr := os.ReadFile(path)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(path, "block"), 0o700); err != nil {
		t.Fatal(err)
	}
	return func() {
		_ = os.RemoveAll(path)
		if readErr == nil {
			if err := os.WriteFile(path, backup, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func waitCondition(t *testing.T, what string, cond func() bool) {
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

// relayPoints counts LAN relay nodes, which is what an import creates.
func relayPoints(a *app) []model.AccessPoint {
	var out []model.AccessPoint
	for _, p := range a.cfg.Points {
		if p.Protocol == model.ProtocolLANRelay {
			out = append(out, p)
		}
	}
	return out
}

// A2: an upgraded configuration that was already sharing must not start
// broadcasting just because the feature exists now.
func TestAcceptanceUpgradeDoesNotAnnounce(t *testing.T) {
	a, backend, _ := discoveryApp(t)
	if _, err := a.store.Update(func(cfg *model.Config) error {
		cfg.Add(model.AccessPoint{ID: "p1", Name: "公司 VPN", Protocol: model.ProtocolATrust,
			Server: "vpn.example.com", Port: 443, Username: "u", InPool: true})
		// Written by an older version: the share was on, discovery was never
		// offered.
		cfg.Settings.LANShare = model.LANShareSettings{
			Enabled: true, PointID: "p1", InterfaceName: "en0",
			PreferredIPv4: "192.168.31.61", Port: 23456, BoundPort: 23456,
			ShareID: "CCCCCCCCCCCCCCCCCCCCCC", CertificateSHA256: strings.Repeat("ab", 32),
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := a.store.Save(); err != nil {
		t.Fatal(err)
	}
	a.setConfig(a.store.Config())
	a.mgr.Apply(a.cfg)
	a.kickLANDiscovery()
	time.Sleep(50 * time.Millisecond)
	if got := backend.announcements(); len(got) != 0 {
		t.Fatalf("升级后自动发布了：%+v", got)
	}
	view := a.lanShare.View()
	if view.DiscoveryEnabled {
		t.Fatal("旧配置被静默当成已允许发现")
	}
	if _, ok := a.lanShare.DiscoverySnapshot(); ok {
		t.Fatal("没有发现偏好时仍允许发布")
	}
}

// A3/A4: the enable form's checkbox is an explicit choice saved with the intent.
func TestAcceptanceEnableFormSavesTheChoice(t *testing.T) {
	a, _, _ := discoveryApp(t)

	// Nothing chosen yet: the form shows the box checked, but opening the panel
	// writes nothing.
	a.openLANShare()
	if !a.lanShareUI.discovery {
		t.Fatal("首次开启表单应当默认勾选")
	}
	if got := a.store.Config().Settings.LANShare.DiscoveryEnabled; got != nil {
		t.Fatalf("只打开弹窗就写了偏好：%v", *got)
	}

	// The user unchecks it: the false must survive a restart.
	a.lanShareUI.discovery = false
	a.enableLANShare()
	waitCondition(t, "enable finished", func() bool {
		a.drainLANShareResults()
		return !a.lanShareUI.busy
	})
	saved := a.store.Config().Settings.LANShare.DiscoveryEnabled
	if saved == nil || *saved {
		t.Fatalf("false 没有被保存：%v", saved)
	}
	a.lanShareUI.open = false

	// Reopening keeps false rather than falling back to the default.
	a.openLANShare()
	if a.lanShareUI.discovery {
		t.Fatal("重新打开时 false 被默认值覆盖")
	}
}

// B11: stopping discovery must not touch the token, the certificate, the
// connection or the share intent.
func TestAcceptanceStoppingDiscoveryKeepsTheShare(t *testing.T) {
	a, _, iface := discoveryApp(t)
	enableShare(t, a, iface, true, "会议室")
	before := a.lanShare.Settings()
	if err := a.lanShare.SetDiscovery(true, "会议室"); err != nil {
		t.Fatal(err)
	}

	if err := a.setLANDiscoveryPreference(false, "会议室"); err != nil {
		t.Fatal(err)
	}
	after := a.lanShare.Settings()
	if after.Enabled != before.Enabled || after.ShareID != before.ShareID ||
		after.Fingerprint != before.Fingerprint || after.PointID != before.PointID {
		t.Fatalf("停止发现改变了共享本身：before=%+v after=%+v", before, after)
	}
	if after.DiscoveryEnabled == nil || *after.DiscoveryEnabled {
		t.Fatalf("偏好没有保存为 false：%v", after.DiscoveryEnabled)
	}
	waitCondition(t, "announcement withdrawn", func() bool {
		return a.discoveryStatus().State == discovery.StatusIdle
	})
}

// B8/B10: only a fully committed Running share may be announced.
func TestAcceptanceOnlyRunningAnnounces(t *testing.T) {
	a, _, iface := discoveryApp(t)
	enableShare(t, a, iface, true, "")
	view := a.lanShare.View()
	if view.State == relay.StateRunning {
		if _, ok := a.lanShare.DiscoverySnapshot(); !ok {
			t.Fatal("Running 时应当有公告")
		}
		return
	}
	if _, ok := a.lanShare.DiscoverySnapshot(); ok {
		t.Fatalf("%s 状态不应发布", view.State)
	}
	// Suspending keeps the intent but must withdraw the announcement.
	if err := a.lanShare.Suspend(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.lanShare.DiscoverySnapshot(); ok {
		t.Fatal("暂停后仍在发布")
	}
}

// A6: a failed save never leaves an announcement behind, and a failed "off"
// save still stops the network for this run.
func TestAcceptanceFailedSaveSemantics(t *testing.T) {
	a, backend, iface := discoveryApp(t)
	// The share starts with discovery off, so nothing is announced yet.
	enableShare(t, a, iface, false, "")

	// Turning it on must save first: a refusing store means no announcement.
	unblock := blockStoreSaves(t, a)
	if err := a.setLANDiscoveryPreference(true, "会议室"); err == nil {
		t.Fatal("保存失败时应当返回错误")
	}
	a.kickLANDiscovery()
	time.Sleep(50 * time.Millisecond)
	if got := backend.announcements(); len(got) != 0 {
		t.Fatalf("保存失败却发布了：%+v", got)
	}
	if a.lanShare.View().DiscoveryEnabled {
		t.Fatal("保存失败后控制器仍认为已允许发现")
	}

	// After the disk recovers the same action publishes.
	unblock()
	if err := a.setLANDiscoveryPreference(true, "会议室"); err != nil {
		t.Fatal(err)
	}
	waitCondition(t, "published", func() bool {
		return a.discoveryStatus().State == discovery.StatusPublished
	})

	// Turning it off stops the network even when the save fails.
	unblock = blockStoreSaves(t, a)
	err := a.setLANDiscoveryPreference(false, "")
	if err == nil || !strings.Contains(err.Error(), "偏好未保存") {
		t.Fatalf("关闭保存失败应当明确提示，得到 %v", err)
	}
	waitCondition(t, "still suppressed", func() bool {
		return a.discoveryStatus().State == discovery.StatusIdle
	})
	if backend.liveCount() != 0 {
		t.Fatalf("关闭后仍有 %d 条公告", backend.liveCount())
	}
	// A later successful save keeps it off instead of resurrecting it.
	unblock()
	if err := a.retryLANDiscoveryPreference(); err != nil {
		t.Fatal(err)
	}
	if got := a.store.Config().Settings.LANShare.DiscoveryEnabled; got == nil || *got {
		t.Fatalf("重试后偏好仍不是 false：%v", got)
	}
	time.Sleep(50 * time.Millisecond)
	if backend.liveCount() != 0 {
		t.Fatal("重试保存后又开始发布了")
	}
}

// D22: a code that does not match the candidate is refused, and nothing is
// written.
func TestAcceptanceCandidateMismatchIsRefused(t *testing.T) {
	a, _, _ := discoveryApp(t)
	code := sampleShareCode()
	a.openRelayImport()
	a.relayImport.tab = 1
	a.relayImport.pinnedKey = "CH-other|en0|192.168.1.99|23456"
	a.relayImport.pinned = discovery.Candidate{
		Instance: "CH-other._connecthub._tcp.local.", ShareID: "other",
		Address: "192.168.1.99", Port: 23456, Interface: "en0",
		DraftVersion: 1, ProtocolVersion: 1,
	}
	a.relayImport.text = code
	a.parseRelayImport()
	if !a.relayImport.parsed {
		t.Fatalf("前置条件：口令应当先解析成功：%s", a.relayImport.err)
	}
	a.submitRelayImport()
	if !strings.Contains(a.relayImport.err, "不一致") {
		t.Fatalf("不一致的口令没有被拒绝：%q", a.relayImport.err)
	}
	if got := relayPoints(a); len(got) != 0 {
		t.Fatalf("拒绝后仍写入了接入点：%+v", got)
	}

	// Clearing the candidate makes the ordinary import path work again.
	a.relayImport.pinnedKey = ""
	a.relayImport.pinned = discovery.Candidate{}
	a.submitRelayImport()
	if got := relayPoints(a); len(got) != 1 {
		t.Fatalf("改为普通导入后没有添加：%+v", got)
	}
}

// D23/D26: discovery never rewrites a saved node, and a forged announcement
// cannot make the app connect somewhere else.
func TestAcceptanceDiscoveryDoesNotTouchSavedNodes(t *testing.T) {
	a, backend, _ := discoveryApp(t)
	a.openRelayImport()
	a.relayImport.tab = 1
	a.relayImport.text = sampleShareCode()
	a.parseRelayImport()
	code := a.relayImport.code
	a.submitRelayImport()
	imported := relayPoints(a)
	if len(imported) != 1 {
		t.Fatalf("导入失败：%+v", imported)
	}
	saved := imported[0]
	before := a.store.Config()

	// Browse and feed a forged record with the same share ID but another
	// address: it must neither rewrite the node nor produce a "join" action.
	a.openLANDiscovery()
	backend.feed([]discovery.Record{
		{Kind: discovery.KindPTR, Instance: discovery.InstanceName(code.ShareID), TTL: 4500, Interface: "en0"},
		{Kind: discovery.KindSRV, Instance: discovery.InstanceName(code.ShareID),
			Host: discovery.HostLabel(code.ShareID), Port: 29999, TTL: 120, Interface: "en0"},
		{Kind: discovery.KindTXT, Instance: discovery.InstanceName(code.ShareID),
			TXT: []string{"dv=1", "pv=1", "sid=" + code.ShareID, "name=伪造"}, TTL: 4500, Interface: "en0"},
		{Kind: discovery.KindA, Host: discovery.HostLabel(code.ShareID), IPv4: "192.168.31.240",
			TTL: 120, Interface: "en0"},
	})
	after := a.store.Config()
	if len(after.Points) != len(before.Points) {
		t.Fatal("发现改动了接入点列表")
	}
	got := after.Points[len(after.Points)-1]
	if got.Server != saved.Server || got.Port != saved.Port ||
		got.Relay == nil || saved.Relay == nil || got.Relay.CertificateSHA256 != saved.Relay.CertificateSHA256 {
		t.Fatalf("发现改写了已保存的节点：%+v", got)
	}
	if existing, same := a.findRelayPointByShareID(code.ShareID); existing == nil || !same {
		t.Fatal("已导入节点应当匹配")
	}
	if existing, _ := a.findRelayPointByShareID(code.ShareID); existing.Server != code.Host {
		t.Fatalf("匹配改动了已保存地址：%s", existing.Server)
	}
}

// C21: browsing a flood of forged candidates must not dial, read credentials or
// write configuration.
func TestAcceptanceBrowsingNeverDials(t *testing.T) {
	a, backend, _ := discoveryApp(t)
	before := a.store.Config()
	// Anything that tried to connect would move a point out of "未登录" or
	// create one; nothing here may change either.
	a.openLANDiscovery()
	backend.feed([]discovery.Record{
		{Kind: discovery.KindPTR, Instance: "CH-forged-1._connecthub._tcp.local.", TTL: 4500, Interface: "en0"},
		{Kind: discovery.KindSRV, Instance: "CH-forged-1._connecthub._tcp.local.",
			Host: "ch-forged.local.", Port: 443, TTL: 120, Interface: "en0"},
		{Kind: discovery.KindTXT, Instance: "CH-forged-1._connecthub._tcp.local.",
			TXT: []string{"dv=1", "pv=1", "sid=AAAAAAAAAAAAAAAAAAAAAA", "name=伪造"}, TTL: 4500, Interface: "en0"},
		{Kind: discovery.KindA, Host: "ch-forged.local.", IPv4: "192.168.31.9", TTL: 120, Interface: "en0"},
	})
	after := a.store.Config()
	if len(after.Points) != len(before.Points) {
		t.Fatalf("浏览写入了配置：%d -> %d", len(before.Points), len(after.Points))
	}
	// Browsing is passive: no session, no credential read, no dial. The
	// manager sees no request because nothing here calls Connect.
	if view, ok := a.mgr.View("p1"); ok && view.State != vpn.StateOffline && view.State != "" {
		t.Fatalf("浏览改动了接入点状态：%+v", view)
	}
}

// D27/E30: when discovery is unavailable the code path still works, and the UI
// says so without inventing a firewall diagnosis.
func TestAcceptanceDiscoveryFailureDegradesHonestly(t *testing.T) {
	a := testApp(t)
	backend := newTestDiscoveryBackend()
	backend.browseErr = errors.New("无法监听 5353")
	a.discoveryBackend = backend
	withLANShare(t, a)
	a.setupLANDiscovery()
	t.Cleanup(a.shutdownLANDiscovery)

	a.openRelayImport()
	if a.relayImport.tab != 0 {
		t.Fatal("有网卡时应当默认进入发现页")
	}
	tt := ui.NewTester(a.view, 1120, 800)
	texts := strings.Join(tt.Texts(), "|")
	if !strings.Contains(texts, "仍然可以粘贴分享口令加入") {
		t.Errorf("发现失败没有给出可用的替代路径；texts = %s", texts)
	}
	for _, bad := range []string{"防火墙拦截", "权限被拒"} {
		if strings.Contains(texts, bad) {
			t.Errorf("没有依据的结论出现在界面上：%q", bad)
		}
	}
	// The paste path still imports.
	a.relayImport.tab = 1
	a.relayImport.text = sampleShareCode()
	a.parseRelayImport()
	a.submitRelayImport()
	if got := relayPoints(a); len(got) != 1 {
		t.Fatalf("发现失败后口令导入也不可用：%+v", got)
	}
}

// E29: the macOS package declares the local-network purpose and the service.
func TestAcceptanceMacPackageDeclaresDiscovery(t *testing.T) {
	script, err := os.ReadFile("scripts/package-mac.sh")
	if err != nil {
		t.Fatal(err)
	}
	text := string(script)
	for _, want := range []string{"NSLocalNetworkUsageDescription", "NSBonjourServices", "_connecthub._tcp"} {
		if !strings.Contains(text, want) {
			t.Errorf("打包脚本缺少 %q", want)
		}
	}
	// The declared service type must match the one the code browses.
	if !strings.Contains(text, strings.TrimSuffix(discovery.ServiceType, ".local.")) {
		t.Errorf("打包脚本里的服务类型与 discovery.ServiceType 不一致")
	}
}
