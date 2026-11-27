package desktop

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/ehzyil/connect-hub/internal/relay"
	relayadapter "github.com/ehzyil/connect-hub/internal/relay/adapter"
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

func (b *testDiscoveryBackend) closedCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.closed
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
func discoveryApp(t *testing.T) (*app, *testDiscoveryBackend, relay.Interface, *appTestSink) {
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
	sink := &appTestSink{names: map[string]string{"p1": "公司 VPN"}, echo: echo}
	installLANShareWith(t, a, sink, lanAddresses{})
	a.setupLANDiscovery()
	t.Cleanup(a.shutdownLANDiscovery)
	return a, backend, iface, sink
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
	a, backend, _, _ := discoveryApp(t)
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
	a, _, _, _ := discoveryApp(t)

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
	a, _, iface, _ := discoveryApp(t)
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
	a, _, iface, _ := discoveryApp(t)
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
	a, backend, iface, _ := discoveryApp(t)
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
	a, _, _, _ := discoveryApp(t)
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
	a, backend, _, _ := discoveryApp(t)
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
	// The forged endpoint (another address and port) must be reported as a
	// different offer, not as the imported node.
	forged := discovery.Candidate{ShareID: code.ShareID, Address: "192.168.31.240", Port: 29999}
	if existing, same := a.findRelayPointByShareID(forged); existing == nil || same {
		t.Fatalf("地址不同的候选被当成了已导入节点：%v %v", existing, same)
	}
	// The saved endpoint still matches exactly.
	savedCand := discovery.Candidate{ShareID: code.ShareID, Address: code.Host, Port: code.Port}
	existing, same := a.findRelayPointByShareID(savedCand)
	if existing == nil || !same {
		t.Fatal("已保存的 endpoint 应当匹配")
	}
	if existing.Server != code.Host {
		t.Fatalf("匹配改动了已保存地址：%s", existing.Server)
	}
	a.relayImport.open = true
	a.relayImport.tab = 0
	a.drainLANDiscovery()
	tt := ui.NewTester(a.view, 1120, 800)
	texts := strings.Join(tt.Texts(), "|")
	if !strings.Contains(texts, "地址不同") {
		t.Fatalf("界面没有提示地址不同：%s", texts)
	}
	for _, bad := range []string{"已导入，待验证"} {
		if strings.Contains(texts, bad) {
			t.Fatalf("地址不同的候选被显示成 %q", bad)
		}
	}
}

// C21: browsing a flood of forged candidates must not dial, read credentials or
// write configuration.
func TestAcceptanceBrowsingNeverDials(t *testing.T) {
	a, backend, _, _ := discoveryApp(t)
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
	script, err := os.ReadFile(filepath.Join(desktopRepoRoot(t), "scripts", "package-mac.sh"))
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

// A9/E30 (spec §9.1.3): the first seconds must read as "still searching", not
// as "there is nothing", and the transition must happen without a user action.
func TestAcceptanceFirstSecondsReadAsSearching(t *testing.T) {
	a, _, _, _ := discoveryApp(t)
	a.lanDisc.ui.searchWindow = 40 * time.Millisecond
	a.openRelayImport()
	a.relayImport.tab = 0
	a.drainLANDiscovery()
	tt := ui.NewTester(a.view, 1120, 800)
	texts := strings.Join(tt.Texts(), "|")
	if !strings.Contains(texts, "正在查找局域网分享") {
		t.Fatalf("首轮没有搜索提示：%s", texts)
	}
	if strings.Contains(texts, "暂未发现分享") {
		t.Fatalf("首轮过早判定没有分享：%s", texts)
	}
	// After the window, the honest empty state takes over on the next frame.
	time.Sleep(60 * time.Millisecond)
	a.drainLANDiscovery()
	a.invalidate()
	tt = ui.NewTester(a.view, 1120, 800)
	texts = strings.Join(tt.Texts(), "|")
	if !strings.Contains(texts, "暂未发现分享") {
		t.Fatalf("搜索窗口结束后没有空态：%s", texts)
	}
}

// A6 (spec §4): a failed "off" save keeps the name the user chose, so a retry
// does not silently drop it.
func TestAcceptanceRetryKeepsThePublicName(t *testing.T) {
	a, _, iface, _ := discoveryApp(t)
	enableShare(t, a, iface, true, "会议室")
	unblock := blockStoreSaves(t, a)
	if err := a.setLANDiscoveryPreference(false, ""); err == nil {
		t.Fatal("保存失败时应当返回错误")
	}
	if name := a.lanShare.Settings().DiscoveryName; name != "会议室" {
		t.Fatalf("保存失败后名称丢了：%q", name)
	}
	unblock()
	if err := a.retryLANDiscoveryPreference(); err != nil {
		t.Fatal(err)
	}
	if name := a.lanShare.Settings().DiscoveryName; name != "会议室" {
		t.Fatalf("重试后名称丢了：%q", name)
	}
	if got := a.store.Config().Settings.LANShare.DiscoveryName; got != "会议室" {
		t.Fatalf("落盘的名称不对：%q", got)
	}
}

// Review: shutting discovery down twice must not panic, and a late page-open
// must not start browsing again after the sockets are gone.
func TestAcceptanceShutdownIsIdempotent(t *testing.T) {
	a, _, _, _ := discoveryApp(t)
	a.openRelayImport()
	a.shutdownLANDiscovery()
	a.shutdownLANDiscovery()
	a.lanDisc.ui.open = false
	a.openLANDiscovery()
	if a.lanDisc.ui.open {
		t.Fatal("退出后仍能开始浏览")
	}
}

// Spec §9.1.5: this machine's own share must not appear in its own list, but a
// colleague who reports the same share ID from another address must.
func TestAcceptanceOwnShareIsFilteredByAddress(t *testing.T) {
	a, backend, iface, _ := discoveryApp(t)
	enableShare(t, a, iface, true, "本机共享")
	own := a.lanShare.Settings()
	a.openRelayImport()

	mk := func(addr string) []discovery.Record {
		return []discovery.Record{
			{Kind: discovery.KindPTR, Instance: discovery.InstanceName(own.ShareID), TTL: 4500, Interface: "en0"},
			{Kind: discovery.KindSRV, Instance: discovery.InstanceName(own.ShareID),
				Host: discovery.HostLabel(own.ShareID), Port: 23456, TTL: 120, Interface: "en0"},
			{Kind: discovery.KindTXT, Instance: discovery.InstanceName(own.ShareID),
				TXT: []string{"dv=1", "pv=1", "sid=" + own.ShareID, "name=同名"}, TTL: 4500, Interface: "en0"},
			{Kind: discovery.KindA, Host: discovery.HostLabel(own.ShareID), IPv4: addr, TTL: 120, Interface: "en0"},
		}
	}
	// Same share ID on a local address: our own instance, hidden.
	backend.feed(mk(iface.IPv4))
	a.drainLANDiscovery()
	if got := len(a.lanDisc.ui.cands); got != 0 {
		t.Fatalf("本机自己的分享没有被过滤：%d", got)
	}
	// Same share ID from a remote address: a real colleague, shown. The local
	// address is withdrawn first, because that is what a responder does when its
	// address changes: with both addresses live at once the assembler keeps one
	// endpoint per instance (cache-flush semantics), and which one it keeps would
	// decide this assertion instead of the filter being tested.
	backend.feed([]discovery.Record{
		{Kind: discovery.KindA, Host: discovery.HostLabel(own.ShareID), IPv4: iface.IPv4, TTL: 0, Interface: "en0"},
	})
	backend.feed(mk("192.168.31.240"))
	a.drainLANDiscovery()
	if got := len(a.lanDisc.ui.cands); got != 1 {
		t.Fatalf("远端同名分享被误过滤：%d", got)
	}
}

// End-to-end over real sockets: A publishes with the production backend, B
// browses with it, joins with A's share code, and B's relay session goes online.
// This is the closest a single machine gets to the two-computer acceptance run.
func TestLiveDiscoveryJoinEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("短模式跳过真实组播端到端")
	}
	iface := localLANAddress(t)
	relayExe := filepath.Join(t.TempDir(), "connect-hub-relay")
	if runtime.GOOS == "windows" {
		relayExe += ".exe"
	}
	build := exec.Command("go", "build", "-mod=readonly", "-o", relayExe, "./cmd/app-relay")
	build.Dir = desktopRepoRoot(t)
	build.Env = append(os.Environ(), "GOWORK=off")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("构建 relay 子进程失败：%v\n%s", err, output)
	}

	// ---- A: the sharing host -------------------------------------------------
	a := testApp(t)
	a.relayExecutable = relayExe
	echo, closeEcho := echoListenerForTest(t)
	t.Cleanup(closeEcho)
	installLANShareWith(t, a, &appTestSink{names: map[string]string{"p1": "公司 VPN"}, echo: echo}, lanAddresses{})
	if _, err := a.store.Update(func(cfg *model.Config) error {
		cfg.Add(model.AccessPoint{ID: "p1", Name: "公司 VPN", Protocol: model.ProtocolATrust,
			Server: "vpn.example.com", Port: 443, Username: "u", InPool: true})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	a.setConfig(a.store.Config())
	a.mgr.Apply(a.cfg)
	a.setupLANDiscovery()
	t.Cleanup(a.shutdownLANDiscovery)
	if err := a.lanShare.Enable(context.Background(), relay.EnableOptions{
		PointID: "p1", InterfaceName: iface.Name, PreferredIPv4: iface.IPv4,
		Discovery: true, DiscoveryName: "端到端分享",
	}); err != nil {
		t.Fatalf("A 开启共享失败：%v", err)
	}
	waitAppShare(t, a, relay.StateRunning)
	code, err := a.lanShare.ShareCode()
	if err != nil {
		t.Fatal(err)
	}
	waitCondition(t, "A 已发布", func() bool {
		return a.discoveryStatus().State == discovery.StatusPublished
	})

	// ---- B: the colleague ----------------------------------------------------
	b := testApp(t)
	b.relayExecutable = relayExe
	b.mgr.Close()
	b.mgr = vpn.NewManager(
		vpn.NewProtocolConnector(vpn.ZJUOptions{
			DataDir: t.TempDir(),
		}, vpn.Registration{Protocol: model.ProtocolLANRelay, Connect: relayadapter.NewConnector(relayadapter.Options{
			Dial: relay.DirectDialer, SaveSnapshot: b.saveRelaySnapshot,
		})}),
		b.credentials, b.bus, b.invalidateCoalesced,
	)
	t.Cleanup(b.mgr.Close)
	b.mgr.Apply(b.cfg)
	b.setupLANDiscovery()
	t.Cleanup(b.shutdownLANDiscovery)
	b.openRelayImport()

	waitCondition(t, "B 发现 A 的分享", func() bool {
		b.drainLANDiscovery()
		for _, cand := range b.lanDisc.ui.cands {
			if cand.ShareID == a.lanShare.Settings().ShareID {
				return true
			}
		}
		return false
	})

	// Join through the discovered candidate with the real share code.
	b.drainLANDiscovery()
	var cand discovery.Candidate
	for _, c := range b.lanDisc.ui.cands {
		if c.ShareID == a.lanShare.Settings().ShareID {
			cand = c
		}
	}
	b.relayImport.pinned = cand
	b.relayImport.pinnedKey = cand.Key()
	b.relayImport.tab = 1
	b.relayImport.text = code
	b.parseRelayImport()
	if err := b.relayImport.err; err != "" {
		t.Fatalf("口令解析失败：%s", err)
	}
	b.submitRelayImport()
	points := relayPoints(b)
	if len(points) != 1 {
		t.Fatalf("加入后没有节点：%+v", points)
	}
	point := points[0]
	if point.Server != cand.Address || point.Port != cand.Port {
		t.Fatalf("节点地址不是发现到的 endpoint：%+v vs %+v", point, cand)
	}
	waitCondition(t, "B 的会话上线", func() bool {
		v, ok := b.mgr.View(point.ID)
		return ok && v.State == vpn.StateOnline
	})
}

// Review: the browsing interface list was built only when a share controller
// existed, so a machine that had never shared anything reported "no LAN
// interface" and could not discover at all - the entire colleague side.
func TestAcceptanceBrowsingWorksWithoutSharing(t *testing.T) {
	a := testApp(t) // no lanShare controller at all
	backend := newTestDiscoveryBackend()
	a.discoveryBackend = backend
	a.setupLANDiscovery()
	t.Cleanup(a.shutdownLANDiscovery)

	ifaces := a.browseInterfaces("")
	if len(ifaces) == 0 {
		t.Skip("本机没有局域网网卡，跳过（需实机覆盖）")
	}
	a.openLANDiscovery()
	if a.lanDisc.ui.err != "" {
		t.Fatalf("没有开启共享也应能浏览：%s", a.lanDisc.ui.err)
	}
	a.openRelayImport()
	if a.relayImport.tab != 0 {
		t.Fatal("有网卡时应当默认进入发现页")
	}
	backend.mu.Lock()
	browsed := len(backend.browsed)
	backend.mu.Unlock()
	if browsed == 0 {
		t.Fatal("浏览会话没有启动")
	}
}

// Spec §4/§12 A6: when the switch-off cannot be saved, the panel must offer a
// retry instead of claiming the preference was stored.
func TestAcceptanceFailedOffSaveOffersARetry(t *testing.T) {
	a, _, iface, _ := discoveryApp(t)
	enableShare(t, a, iface, true, "会议室")
	a.openLANShare()
	unblock := blockStoreSaves(t, a)
	on := a.lanShare.View().DiscoveryEnabled
	a.toggleLANDiscovery(!on)
	waitCondition(t, "switch-off handled", func() bool {
		a.drainLANShareResults()
		return !a.lanShareUI.discoveryBusy
	})
	if !a.lanShareUI.discoverySavePending {
		t.Fatalf("保存失败没有进入待重试状态：%q", a.lanShareUI.err)
	}
	tt := ui.NewTester(a.view, 1120, 800)
	texts := strings.Join(tt.Texts(), "|")
	for _, want := range []string{"偏好没有保存成功", "重试保存"} {
		if !strings.Contains(texts, want) {
			t.Fatalf("面板缺少 %q：%s", want, texts)
		}
	}
	// The retry clears the flag and writes the preference.
	unblock()
	a.retryLANDiscoverySave()
	waitCondition(t, "retry saved", func() bool {
		a.drainLANShareResults()
		return !a.lanShareUI.discoveryBusy
	})
	if a.lanShareUI.discoverySavePending {
		t.Fatal("重试成功后仍显示待重试")
	}
	if got := a.store.Config().Settings.LANShare.DiscoveryEnabled; got == nil || *got {
		t.Fatalf("重试后偏好仍不是 false：%v", got)
	}
}

// Unused discovery has no workers or sockets. Opening the browser owns a
// bounded search deadline; closing it releases that deadline and its session.
func TestIdleDiscoveryIsFree(t *testing.T) {
	a := testApp(t)
	backend := newTestDiscoveryBackend()
	a.discoveryBackend = backend
	before := len(optionalWorkerStacks())
	a.setupLANDiscovery()
	t.Cleanup(a.shutdownLANDiscovery)
	waitOptionalWorkers(t, before)
	// Idle discovery must not hold a single file descriptor: no socket, no
	// multicast membership, nothing for a user who never enables it.
	if runtime.GOOS == "linux" {
		beforeFD := openFDs(t)
		time.Sleep(2100 * time.Millisecond) // at least one safety tick
		if afterFD := openFDs(t); afterFD != beforeFD {
			t.Fatalf("空闲发现持有 %d 个文件描述符（原 %d）", afterFD-beforeFD, beforeFD)
		}
	}
	// No page is open and nothing is searching, so the coordinator must not ask
	// for a frame - i.e. no permanent repaint for everyone.
	if a.lanDiscoveryNeedsFrame() {
		t.Fatal("空闲状态下仍然要求重绘")
	}
	// Even after the safety tick fires, nothing is painted.
	time.Sleep(50 * time.Millisecond)
	a.syncLANDiscovery()
	if a.lanDiscoveryNeedsFrame() {
		t.Fatal("兜底 tick 触发了重绘")
	}
	// While the page is open and still searching, one frame per tick is
	// expected, and it stops once the window expires.
	a.openLANDiscovery()
	if !a.lanDiscoveryNeedsFrame() {
		t.Fatal("搜索窗口内应当允许刷新搜索提示")
	}
	a.lanDisc.ui.searchWindow = 10 * time.Millisecond
	time.Sleep(20 * time.Millisecond)
	a.drainLANDiscovery()
	if a.lanDiscoveryNeedsFrame() {
		t.Fatal("搜索窗口结束后不应继续请求帧")
	}
	a.shutdownLANDiscovery()
	waitOptionalWorkers(t, before)
}

// openFDs counts the process's open descriptors, so a test can prove the idle
// feature holds no socket.
func openFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("无法读取 /proc/self/fd：%v", err)
	}
	return len(entries)
}

// Review round 5: the discovery page renders per frame, so it must not enumerate
// interfaces per frame, and the browsing set must carry the interface subnet so
// reflected announcements can be dropped.
func TestAcceptanceBrowsingSetIsCachedAndCarriesTheSubnet(t *testing.T) {
	a, _, _, _ := discoveryApp(t)
	ifaces := a.browseInterfaces("")
	if len(ifaces) == 0 {
		t.Skip("本机没有局域网网卡，跳过")
	}
	if ifaces[0].Subnet == "" {
		t.Fatal("浏览网卡没有带子网信息，反射公告将无法识别")
	}
	// Two calls in the same second must not re-enumerate: the second returns the
	// cached copy (same content, no syscalls).
	again := a.browseInterfaces("")
	if len(again) != len(ifaces) {
		t.Fatalf("缓存前后数量不同：%d vs %d", len(ifaces), len(again))
	}
	a.lanDisc.mu.Lock()
	cached := len(a.lanDisc.localAddrs) > 0
	a.lanDisc.mu.Unlock()
	if !cached {
		t.Fatal("网卡列表没有被缓存")
	}
	if len(a.browseInterfaces("")) > maxBrowsedInterfaces {
		t.Fatal("浏览网卡数量没有上限")
	}
}

// The picker must list every adapter even though browsing is bounded, otherwise
// an interface beyond the bound could never be selected.
func TestAcceptanceInterfacePickerIsNotCapped(t *testing.T) {
	a, _, _, _ := discoveryApp(t)
	all := a.allLANInterfaces()
	browsed := a.browseInterfaces("")
	if len(all) < len(browsed) {
		t.Fatalf("选择器比浏览集合还少：%d < %d", len(all), len(browsed))
	}
	labels, byLabel := a.discoveryInterfaceChoices()
	if len(labels) != len(all) {
		t.Fatalf("选择器列出 %d 个，实际 %d 个", len(labels), len(all))
	}
	for _, label := range labels {
		if byLabel[label] == "" {
			t.Fatalf("选择项 %q 没有对应网卡", label)
		}
	}
}

// Spec §8.2: a waiting share announces as soon as the same instance starts
// running, driven by the controller's change notification - no kick, no frame.
func TestAcceptanceWaitingShareAnnouncesWhenItStarts(t *testing.T) {
	a, backend, iface, sink := discoveryApp(t)
	sink.setOffline(true)
	if err := a.lanShare.Enable(context.Background(), relay.EnableOptions{
		PointID: "p1", InterfaceName: iface.Name, PreferredIPv4: iface.IPv4,
		Discovery: true, DiscoveryName: "会议室",
	}); err != nil {
		t.Fatal(err)
	}
	waitAppShare(t, a, relay.StateWaiting)
	time.Sleep(50 * time.Millisecond)
	if got := backend.announcements(); len(got) != 0 {
		t.Fatalf("等待状态发布了：%+v", got)
	}

	// The access point comes up. Nothing here calls the discovery coordinator:
	// the controller's notification must be what starts the announcement.
	sink.setOffline(false)
	if err := a.lanShare.Retry(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitAppShare(t, a, relay.StateRunning)
	waitCondition(t, "announcement after running", func() bool {
		return a.discoveryStatus().State == discovery.StatusPublished
	})
	anns := backend.announcements()
	if len(anns) == 0 || anns[len(anns)-1].Name != "会议室" {
		t.Fatalf("恢复后没有发布：%+v", anns)
	}
	if anns[len(anns)-1].Port != a.lanShare.View().Port {
		t.Fatalf("公告端口不是实际绑定端口：%d vs %d", anns[len(anns)-1].Port, a.lanShare.View().Port)
	}
}

// Spec §8.4: quitting withdraws the announcement before the listener goes away.
func TestAcceptanceShutdownWithdrawsTheAnnouncement(t *testing.T) {
	a, backend, iface, _ := discoveryApp(t)
	enableShare(t, a, iface, true, "会议室")
	waitCondition(t, "published", func() bool {
		return a.discoveryStatus().State == discovery.StatusPublished
	})
	if backend.liveCount() != 1 {
		t.Fatalf("前置条件：应当有一条公告，实际 %d", backend.liveCount())
	}
	a.shutdownLANShare()
	if backend.liveCount() != 0 {
		t.Fatalf("退出后仍有 %d 条公告", backend.liveCount())
	}
	if got := backend.closedCount(); got == 0 {
		t.Fatal("退出时没有撤销公告")
	}
}

// Round 6: a failed switch-off keeps announcing suppressed for this run. If the
// user then turns the share off and on again with discovery checked, the new
// explicit enable must announce - the old suppression belongs to the previous
// instance.
func TestAcceptanceReEnableClearsTheFailedOffSuppression(t *testing.T) {
	a, backend, iface, _ := discoveryApp(t)
	enableShare(t, a, iface, true, "会议室")
	waitCondition(t, "published", func() bool {
		return a.discoveryStatus().State == discovery.StatusPublished
	})

	// The switch-off cannot be saved: the network stops, the preference stays.
	unblock := blockStoreSaves(t, a)
	a.toggleLANDiscovery(false)
	waitCondition(t, "suppressed", func() bool {
		a.drainLANShareResults()
		return !a.lanShareUI.discoveryBusy
	})
	if backend.liveCount() != 0 {
		t.Fatal("前置条件：关闭发现后应已撤销公告")
	}

	// The disk recovers; the user closes the share and enables it again with
	// discovery checked.
	unblock()
	if err := a.lanShare.Disable(context.Background()); err != nil {
		t.Fatal(err)
	}
	enableShare(t, a, iface, true, "会议室")
	waitCondition(t, "announcement after re-enable", func() bool {
		return backend.liveCount() == 1
	})
}

// Round 7: the enable form must not render the same control text twice, and the
// disclosure sentence has to be there (the user is choosing to broadcast).
func TestAcceptanceEnableFormHasNoDuplicateDiscoveryLabel(t *testing.T) {
	a, _, _, _ := discoveryApp(t)
	a.openLANShare()
	texts := ui.NewTester(a.view, 1120, 900).Texts()
	joined := strings.Join(texts, "|")
	if got := strings.Count(joined, "允许同一网络的同事发现"); got != 1 {
		t.Fatalf("勾选项文字出现 %d 次：%s", got, joined)
	}
	if !strings.Contains(joined, "加入仍需分享口令") {
		t.Fatalf("缺少公开范围说明：%s", joined)
	}
	if !strings.Contains(joined, "不会使用 VPN 名称") {
		t.Fatalf("缺少默认名称说明：%s", joined)
	}
}
