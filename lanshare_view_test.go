package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"

	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/ehzyil/connect-hub/internal/relay"
	"github.com/ehzyil/connect-hub/internal/routing"
	"github.com/ehzyil/connect-hub/internal/store"
	"github.com/ehzyil/connect-hub/internal/vpn"
	"github.com/ehzyil/connect-hub/internal/workeripc"
)

// testRelaySink is the controller's outside world inside the UI tests: one
// access point, no listener of its own (the controller binds a real one only when
// it can, and these tests never enable it).
type testRelaySink struct {
	mu      sync.Mutex
	points  map[string]string
	offline bool
}

func (s *testRelaySink) AcquireSource(ctx context.Context, id string) (relay.Source, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.points[id]; !ok {
		return nil, relay.ErrPointMissing
	}
	return nil, relay.ErrPointNotReady
}

func (s *testRelaySink) PointName(id string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.points[id]
}

func (s *testRelaySink) PointExists(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.points[id]
	return ok
}

type emptyNets struct{}

func (emptyNets) LANCandidates() []relay.Interface {
	return []relay.Interface{{Name: "test0", IPv4: "127.0.0.1"}}
}

// withLANShare installs a controller on the test app so the UI can be exercised
// without a real share.
func withLANShare(t *testing.T, a *app) *testRelaySink {
	t.Helper()
	sink := &testRelaySink{points: map[string]string{}}
	for _, p := range a.cfg.Points {
		sink.points[p.ID] = p.Name
	}
	ctrl := relay.NewController(store.RelayShareStore{Store: a.store}, sink, emptyNets{}, nil, a.invalidate)
	a.lanShare = ctrl
	a.lanShareUI.results = make(chan lanShareResult, 4)
	t.Cleanup(func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		_ = ctrl.Shutdown(ctx)
	})
	return sink
}

// reopenTestApp builds a second app over an existing data directory, which is
// what an application restart looks like to the manager and the store.
func reopenTestApp(t *testing.T, dir string) *app {
	t.Helper()
	st, err := store.Open(dir, store.NewMemorySecrets())
	if err != nil {
		t.Fatal(err)
	}
	a := &app{store: st, dir: dir, bus: vpn.NewLogBus(50), icon: loadAppIcon()}
	a.cfg = st.Config()
	a.mgr = vpn.NewManager(
		func(context.Context, model.AccessPoint, vpn.Credentials) (vpn.Session, error) {
			return stubSession{ip: "10.10.1.23"}, nil
		},
		a.credentials, a.bus, a.invalidate,
	)
	t.Cleanup(a.mgr.Close)
	a.mgr.Apply(a.cfg)
	withLANShare(t, a)
	return a
}

func sampleShareCode() string {
	payload := map[string]any{
		"v":     1,
		"h":     "192.168.1.50",
		"p":     23456,
		"sid":   base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef")),
		"token": base64.RawURLEncoding.EncodeToString(bytes32()),
		"fp":    strings.Repeat("ab", 32),
		"name":  "现场主机",
	}
	b, _ := json.Marshal(payload)
	return "connect-hub://relay/v1#" + base64.RawURLEncoding.EncodeToString(b)
}

func TestSettingsShowsLANShareEntry(t *testing.T) {
	a := testApp(t)
	withLANShare(t, a)
	a.openSettingsAt(settingGeneral)
	tt := ui.NewTester(a.view, 1120, 800)
	texts := strings.Join(tt.Texts(), "|")
	for _, want := range []string{"局域网分享", "开启共享"} {
		if !strings.Contains(texts, want) {
			t.Errorf("settings lacks %q; texts = %s", want, texts)
		}
	}
}

// TestOpeningSharePanelDoesNotListen: opening the panel is a UI action only.
func TestOpeningSharePanelDoesNotListen(t *testing.T) {
	a := testApp(t)
	withLANShare(t, a)
	a.openLANShare()
	if view := a.lanShare.View(); view.Enabled || view.State != relay.StateOff {
		t.Fatalf("opening the panel changed the share state: %+v", view)
	}
	tt := ui.NewTester(a.view, 1120, 800)
	texts := strings.Join(tt.Texts(), "|")
	for _, want := range []string{"局域网分享", "开启共享", "共享整个接入点"} {
		if !strings.Contains(texts, want) {
			t.Errorf("panel lacks %q; texts = %s", want, texts)
		}
	}
	// No resource-selection UI exists: the whole access point is shared.
	for _, unwanted := range []string{"资源勾选", "选择资源"} {
		if strings.Contains(texts, unwanted) {
			t.Errorf("panel must not offer resource selection, found %q", unwanted)
		}
	}
}

func TestRelayImportPreviewIsLocalAndAddsDisabledAutoconnect(t *testing.T) {
	a := testApp(t)
	withLANShare(t, a)
	code := sampleShareCode()
	a.openRelayImport()
	a.relayImport.text = code
	a.parseRelayImport()
	if !a.relayImport.parsed {
		t.Fatalf("valid share code not parsed: %s", a.relayImport.err)
	}
	tt := ui.NewTester(a.view, 1120, 800)
	texts := strings.Join(tt.Texts(), "|")
	for _, want := range []string{"导入同事分享", "VPN 资源走共享主机，公网走本机", "现场主机", "192.168.1.50:23456"} {
		if !strings.Contains(texts, want) {
			t.Errorf("preview lacks %q; texts = %s", want, texts)
		}
	}
	// Preview must not have created anything yet.
	if len(a.cfg.Points) != 0 {
		t.Fatal("preview created an access point")
	}

	a.submitRelayImport()
	cfg := a.store.Config()
	if len(cfg.Points) != 1 {
		t.Fatalf("import did not add a point: %+v", cfg.Points)
	}
	p := cfg.Points[0]
	if p.Protocol != model.ProtocolLANRelay {
		t.Fatalf("protocol = %q", p.Protocol)
	}
	if p.AutoConnect {
		t.Fatal("an imported node must not auto-connect at startup")
	}
	if !p.InPool {
		t.Fatal("an imported node joins the pool")
	}
	if p.SocksPort != 0 {
		t.Fatalf("an imported node must not take a SOCKS port: %d", p.SocksPort)
	}
	if p.Relay == nil || p.Relay.ShareID == "" || p.Relay.CertificateSHA256 == "" {
		t.Fatalf("relay identity missing: %+v", p.Relay)
	}
	if pin, err := a.store.Password(p.ID); err != nil || pin == "" {
		t.Fatalf("share token not stored: %q %v", pin, err)
	}
	// Importing does not switch on A's share or B's system proxy.
	if a.lanShare.View().Enabled {
		t.Fatal("importing enabled the local share")
	}
	if a.sysProxyOn.Load() {
		t.Fatal("importing enabled the system proxy")
	}
}

func bytes32() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte('A' + i%26)
	}
	return b
}

func TestRelayImportRejectsDuplicates(t *testing.T) {
	a := testApp(t)
	withLANShare(t, a)
	code := sampleShareCode()
	a.openRelayImport()
	a.relayImport.text = code
	a.parseRelayImport()
	a.submitRelayImport()
	first := a.store.Config().Points[0]

	a.openRelayImport()
	a.relayImport.text = code
	a.parseRelayImport()
	a.submitRelayImport()
	cfg := a.store.Config()
	if len(cfg.Points) != 1 {
		t.Fatalf("duplicate import created a second node: %d", len(cfg.Points))
	}
	if cfg.Points[0].ID != first.ID {
		t.Fatal("duplicate import replaced the node")
	}
	if !strings.Contains(a.relayImport.err, "已经导入") {
		t.Fatalf("duplicate was not explained: %q", a.relayImport.err)
	}
}

func TestRelayImportRejectsBrokenCodes(t *testing.T) {
	a := testApp(t)
	withLANShare(t, a)
	for _, text := range []string{
		"随便一段文字",
		"connect-hub://relay/v1#",
		"connect-hub://relay/v1#!!!",
		"hub://relay?token=abc",
	} {
		a.openRelayImport()
		a.relayImport.text = text
		a.parseRelayImport()
		if a.relayImport.parsed {
			t.Fatalf("broken code parsed: %q", text)
		}
		if a.relayImport.err == "" {
			t.Fatalf("broken code had no explanation: %q", text)
		}
	}
	if len(a.store.Config().Points) != 0 {
		t.Fatal("a broken code created a node")
	}
}

// TestCopyCodeNeedsRunningShare: a waiting share must not hand out a code.
func TestCopyCodeNeedsRunningShare(t *testing.T) {
	a := testApp(t)
	withLANShare(t, a)
	if _, err := a.lanShareCode(); err == nil {
		t.Fatal("a disabled share produced a code")
	}
	a.copyLANShareCode()
	if a.lanShareUI.notice != "" && strings.Contains(a.lanShareUI.notice, "已复制") {
		t.Fatal("a disabled share reported a successful copy")
	}
}

// TestShareStripAppearsOnlyWhenEnabled keeps the main window clean by default.
func TestShareStripAppearsOnlyWhenEnabled(t *testing.T) {
	a := testApp(t)
	withLANShare(t, a)
	tt := ui.NewTester(a.view, 1120, 800)
	if strings.Contains(strings.Join(tt.Texts(), "|"), "局域网分享已开启") {
		t.Fatal("status strip shown while the share is off")
	}
}

func TestLANSharePointSelectionDefaultsToOnlinePoint(t *testing.T) {
	a := testApp(t)
	withLANShare(t, a)
	if _, err := a.store.Update(func(cfg *model.Config) error {
		cfg.Add(model.AccessPoint{
			Name: "公司 VPN", Protocol: model.ProtocolATrust, Server: "vpn.example.com",
			Port: 443, Username: "u", InPool: true,
		})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	a.setConfig(a.store.Config())
	a.mgr.Apply(a.cfg)
	a.mgr.Connect(a.cfg.Points[0].ID)
	a.openLANShare()
	if a.lanShareUI.pointID == "" {
		t.Fatal("share panel did not preselect a point")
	}
	// A relay node must never be offered for sharing.
	if _, err := a.store.Update(func(cfg *model.Config) error {
		cfg.Add(model.AccessPoint{
			Name: "同事分享", Protocol: model.ProtocolLANRelay, Server: "192.168.1.9",
			Port: 1234, InPool: true,
			Relay: &model.RelayPointOptions{Version: 1, ShareID: base64.RawURLEncoding.EncodeToString([]byte("aaaaaaaaaaaaaaaa")), CertificateSHA256: strings.Repeat("cd", 32)},
		})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	a.setConfig(a.store.Config())
	a.mgr.Apply(a.cfg)
	for _, v := range a.shareablePoints() {
		if v.Protocol == model.ProtocolLANRelay {
			t.Fatal("a relay node was offered as a share source")
		}
	}
}

// TestRelayImportRollsBackOnSaveFailure: a failed Save must not leave the node in
// memory and must report the failure instead of pretending success.
func TestRelayImportRollsBackOnSaveFailure(t *testing.T) {
	a := testApp(t)
	withLANShare(t, a)
	// Make the configuration unwritable: a directory where config.json belongs
	// makes the atomic rename fail.
	path := filepath.Join(a.store.Dir(), "config.json")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	code := sampleShareCode()
	a.openRelayImport()
	a.relayImport.text = code
	a.parseRelayImport()
	a.submitRelayImport()
	if a.relayImport.err == "" {
		t.Fatal("a failed save was not reported")
	}
	if len(a.store.Config().Points) != 0 {
		t.Fatalf("failed save left the node in memory: %+v", a.store.Config().Points)
	}
}

// TestLANShareWording pins the product wording the objective fixes: the entry is
// 局域网分享 and the buttons are 开启共享 / 关闭共享.
func TestLANShareWording(t *testing.T) {
	running := relay.View{State: relay.StateRunning, Address: "192.168.1.50", Port: 23456}
	if got := lanShareStateText(running); !strings.Contains(got, "分享已开启") {
		t.Fatalf("running text = %q", got)
	}
	waiting := relay.View{State: relay.StateWaiting, Enabled: true}
	if got := lanShareStateText(waiting); !strings.Contains(got, "等待接入点连接") {
		t.Fatalf("waiting text = %q", got)
	}
	blocked := relay.View{State: relay.StateBlocked, Enabled: true, Failure: "端口被占用"}
	if got := lanShareStateText(blocked); !strings.Contains(got, "端口被占用") {
		t.Fatalf("blocked text = %q", got)
	}
	if got := lanShareStateText(relay.View{State: relay.StateOff}); !strings.Contains(got, "未开启") {
		t.Fatalf("off text = %q", got)
	}
}

func TestRelayDiagnosePanelAndMissingToken(t *testing.T) {
	a := testApp(t)
	withLANShare(t, a)
	// A relay node whose credential is gone must report that, not panic.
	if _, err := a.store.Update(func(cfg *model.Config) error {
		cfg.Add(model.AccessPoint{
			Name: "同事分享", Protocol: model.ProtocolLANRelay, Server: "192.168.1.50",
			Port: 23456, InPool: true,
			Relay: &model.RelayPointOptions{
				Version: 1, ShareID: base64.RawURLEncoding.EncodeToString([]byte("aaaaaaaaaaaaaaaa")),
				CertificateSHA256: strings.Repeat("ab", 32),
			},
		})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	a.setConfig(a.store.Config())
	a.mgr.Apply(a.cfg)
	point := a.cfg.Points[0]
	a.openRelayDiagnose(point.ID)
	if a.relayDiagnose.running {
		t.Fatal("diagnose should fail fast without a stored token")
	}
	if !strings.Contains(a.relayDiagnose.err, "口令") {
		t.Fatalf("missing token not explained: %q", a.relayDiagnose.err)
	}
	tt := ui.NewTester(a.view, 1120, 800)
	if texts := strings.Join(tt.Texts(), "|"); !strings.Contains(texts, "连接诊断") {
		t.Fatalf("diagnose panel not rendered; texts = %s", texts)
	}
}

// TestLANShareSelfDiagnoseShowsRealState proves the local check reports the
// controller state instead of a hard-coded success.
func TestLANShareSelfDiagnoseShowsRealState(t *testing.T) {
	a := testApp(t)
	withLANShare(t, a)
	a.openLANShareDiagnose()
	lines := strings.Join(a.relayDiagnose.lines, "\n")
	if !strings.Contains(lines, "未开启") {
		t.Fatalf("self-diagnose hid the off state:\n%s", lines)
	}
	if !strings.Contains(lines, "整个接入点") {
		t.Fatalf("self-diagnose did not state the scope:\n%s", lines)
	}
}

// TestRelayNodeNeverOpensVPNEditor: the VPN form would rewrite the protocol and
// drop the share identity on save, so a relay node opens its own panel.
func TestRelayNodeNeverOpensVPNEditor(t *testing.T) {
	a := testApp(t)
	withLANShare(t, a)
	if _, err := a.store.Update(func(cfg *model.Config) error {
		cfg.Add(model.AccessPoint{
			Name: "同事分享", Protocol: model.ProtocolLANRelay, Server: "192.168.1.50",
			Port: 23456, InPool: true,
			Relay: &model.RelayPointOptions{
				Version: 1, ShareID: base64.RawURLEncoding.EncodeToString([]byte("aaaaaaaaaaaaaaaa")),
				CertificateSHA256: strings.Repeat("ab", 32),
			},
		})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	a.setConfig(a.store.Config())
	a.mgr.Apply(a.cfg)
	point := a.cfg.Points[0]
	view, ok := a.mgr.View(point.ID)
	if !ok {
		t.Fatal("relay point missing from the manager")
	}
	a.openEditor(view)
	if a.editor.open {
		t.Fatal("a relay node opened the VPN editor")
	}
	if !a.relayPoint.open || a.relayPoint.pointID != point.ID {
		t.Fatal("a relay node did not open its own panel")
	}
	tt := ui.NewTester(a.view, 1120, 800)
	texts := strings.Join(tt.Texts(), "|")
	for _, want := range []string{"局域网中继接入点", "192.168.1.50:23456", "连接诊断"} {
		if !strings.Contains(texts, want) {
			t.Errorf("relay panel lacks %q; texts = %s", want, texts)
		}
	}
	// The panel must not offer VPN credentials.
	for _, unwanted := range []string{"用户名", "登录域", "验证码"} {
		if strings.Contains(texts, unwanted) {
			t.Errorf("relay panel shows VPN login field %q", unwanted)
		}
	}
}

// TestDeletingRelayNodeDropsCache keeps a deleted node from leaving a protection
// record that can never be verified again.
func TestDeletingRelayNodeDropsCache(t *testing.T) {
	a := testApp(t)
	withLANShare(t, a)
	if _, err := a.store.Update(func(cfg *model.Config) error {
		cfg.Add(model.AccessPoint{
			Name: "同事分享", Protocol: model.ProtocolLANRelay, Server: "192.168.1.50",
			Port: 23456, InPool: true,
			Relay: &model.RelayPointOptions{
				Version: 1, ShareID: base64.RawURLEncoding.EncodeToString([]byte("aaaaaaaaaaaaaaaa")),
				CertificateSHA256: strings.Repeat("ab", 32),
			},
		})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	a.setConfig(a.store.Config())
	a.mgr.Apply(a.cfg)
	point := a.cfg.Points[0]
	if err := a.store.SaveRelayKnown(point.ID, store.RelaySource{ShareID: point.Relay.ShareID, Fingerprint: point.Relay.CertificateSHA256, Label: "src"}, &workeripc.ResourceSnapshot{
		Tunnel:  "ipv4-l3",
		IPRules: []workeripc.IPRule{{Min: "10.5.0.0", Max: "10.5.0.9", PortMin: 443, PortMax: 443, Protocol: "tcp"}},
	}); err != nil {
		t.Fatal(err)
	}
	a.removePoint(point.ID)
	if known, err := a.store.LoadRelayKnown(point.ID); err != nil || known != nil {
		t.Fatalf("cache survived node deletion: %+v %v", known, err)
	}
	a.setConfig(a.store.Config())
	if len(a.cfg.Points) != 0 {
		t.Fatal("node was not deleted")
	}
}

// TestLoadRelayKnownProtectsAcrossRestart is the B-side restart requirement: a
// cached managed target must not become "direct" after the app restarts, and a
// cache that disappeared must turn the protection gate on instead of silently
// letting it through.
func TestLoadRelayKnownProtectsAcrossRestart(t *testing.T) {
	a := testApp(t)
	withLANShare(t, a)
	if _, err := a.store.Update(func(cfg *model.Config) error {
		point := model.AccessPoint{
			Name: "同事分享", Protocol: model.ProtocolLANRelay, Server: "192.168.1.50",
			Port: 23456, InPool: true,
			Relay: &model.RelayPointOptions{
				Version: 1, ShareID: base64.RawURLEncoding.EncodeToString([]byte("aaaaaaaaaaaaaaaa")),
				CertificateSHA256: strings.Repeat("ab", 32),
			},
		}
		cfg.Add(point)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	a.setConfig(a.store.Config())
	a.mgr.Apply(a.cfg)
	point := a.cfg.Points[0]

	// First run: a verified snapshot is stored and the marker is flipped.
	resources := &workeripc.ResourceSnapshot{
		Tunnel:  "ipv4-l3",
		IPRules: []workeripc.IPRule{{Min: "10.5.0.0", Max: "10.5.255.255", PortMin: 443, PortMax: 443, Protocol: "tcp"}},
	}
	ident := vpn.RelaySnapshotSource{ShareID: point.Relay.ShareID, Fingerprint: point.Relay.CertificateSHA256}
	if err := a.saveRelaySnapshot(point.ID, ident, resources); err != nil {
		t.Fatalf("saveRelaySnapshot: %v", err)
	}
	// The background hook only writes the Store and asks the UI thread to
	// refresh; it must not touch the UI copy of the configuration itself.
	if p := a.cfg.Points[0]; p.Relay != nil && p.Relay.HistoryInitialized {
		t.Fatal("the background hook published the marker into the UI configuration")
	}
	if !a.cfgReload.Load() {
		t.Fatal("a background config write did not request a UI reload")
	}
	a.applyPendingConfigReload() // what the UI thread does before rendering
	if p := a.cfg.Points[0]; p.Relay == nil || !p.Relay.HistoryInitialized {
		t.Fatal("history marker was not visible after the UI reload")
	}
	if a.mgr.RelayHistoryUnverified() {
		t.Fatal("the gate should stay off after a successful cache write")
	}

	// Restart: the same data directory, a brand-new store and manager.
	fresh := reopenTestApp(t, a.store.Dir())
	fresh.loadRelayKnown()
	if fresh.mgr.RelayHistoryUnverified() {
		t.Fatal("a valid cache turned the gate on")
	}
	decision := fresh.mgr.PreviewRoute(routing.Request{Network: "tcp", Address: "10.5.1.2:443", Entry: "统一代理"})
	if decision.Action == "direct" {
		t.Fatalf("cached managed target became direct after restart: %+v", decision)
	}

	// A missing cache with the marker still set must be treated as a gap.
	if err := a.store.DeleteRelayKnown(point.ID); err != nil {
		t.Fatal(err)
	}
	after := reopenTestApp(t, a.store.Dir())
	after.loadRelayKnown()
	if !after.mgr.RelayHistoryUnverified() {
		t.Fatal("a missing cache after initialisation did not enable the gate")
	}
	// The node is also held out of the automatic login set, while a manual login
	// stays available as the repair path.
	if !after.mgr.RelayAutoConnectBlocked(point.ID) {
		t.Fatal("the unverifiable node was left in the auto-connect set")
	}
	if n := after.mgr.ConnectAll(true); n != 0 {
		t.Fatalf("the unverifiable node auto-connected (n=%d)", n)
	}
}

// TestLANSharePanelAtMinimumWindow keeps the panel usable at the app's minimum
// window size: the actions must still be rendered, not clipped out of the tree.
func TestLANSharePanelAtMinimumWindow(t *testing.T) {
	a := testApp(t)
	withLANShare(t, a)
	if _, err := a.store.Update(func(cfg *model.Config) error {
		cfg.Add(model.AccessPoint{Name: "公司 VPN", Protocol: model.ProtocolATrust, Server: "vpn.example.com", Port: 443, Username: "u", InPool: true})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	a.setConfig(a.store.Config())
	a.mgr.Apply(a.cfg)
	a.openLANShare()
	tt := ui.NewTester(a.view, 720, 520)
	texts := strings.Join(tt.Texts(), "|")
	for _, want := range []string{"局域网分享", "共享接入点", "开启共享"} {
		if !strings.Contains(texts, want) {
			t.Errorf("panel at 720x520 lacks %q; texts = %s", want, texts)
		}
	}
	// The import panel must also fit.
	a.lanShareUI.open = false
	a.openRelayImport()
	tt2 := ui.NewTester(a.view, 720, 520)
	if texts := strings.Join(tt2.Texts(), "|"); !strings.Contains(texts, "添加并连接") {
		t.Errorf("import panel at 720x520 lacks its action; texts = %s", texts)
	}
}

// TestRelayPointOffersExplicitSystemProxy: connecting a share must not touch the
// system proxy, but the node panel offers the explicit step and explains why it
// may be unavailable on this platform.
func TestRelayPointOffersExplicitSystemProxy(t *testing.T) {
	a := testApp(t)
	withLANShare(t, a)
	if _, err := a.store.Update(func(cfg *model.Config) error {
		cfg.Add(model.AccessPoint{
			Name: "同事分享", Protocol: model.ProtocolLANRelay, Server: "192.168.1.50",
			Port: 23456, InPool: true,
			Relay: &model.RelayPointOptions{
				Version: 1, ShareID: base64.RawURLEncoding.EncodeToString([]byte("aaaaaaaaaaaaaaaa")),
				CertificateSHA256: strings.Repeat("ab", 32),
			},
		})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	a.setConfig(a.store.Config())
	a.mgr.Apply(a.cfg)
	point := a.cfg.Points[0]
	if err := a.store.SetPassword(point.ID, "share-token-for-test"); err != nil {
		t.Fatal(err)
	}
	a.mgr.Connect(point.ID)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if v, ok := a.mgr.View(point.ID); ok && v.State == vpn.StateOnline {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	a.openRelayPoint(point.ID)
	texts := strings.Join(ui.NewTester(a.view, 1120, 800).Texts(), "|")
	if supportsSystemProxy() {
		if !strings.Contains(texts, "开启系统代理") && !strings.Contains(texts, "系统代理已开启") {
			t.Fatalf("panel lacks the explicit system proxy step; texts = %s", texts)
		}
	} else if !strings.Contains(texts, "系统代理当前不可开启") {
		t.Fatalf("panel does not explain the missing platform support; texts = %s", texts)
	}
	if a.sysProxyOn.Load() {
		t.Fatal("opening the panel changed the system proxy")
	}
}

// TestRelayProtocolLabel keeps a relay node out of the aTrust group in the list.
func TestRelayProtocolLabel(t *testing.T) {
	if got := protocolLabel(model.ProtocolLANRelay); got != "局域网中继" {
		t.Fatalf("protocolLabel(lan_relay) = %q", got)
	}
	if got := protocolLabel(model.ProtocolATrust); got != "aTrust" {
		t.Fatalf("protocolLabel(atrust) = %q", got)
	}
	if got := protocolLabel(model.ProtocolEasyConnect); got != "EasyConnect" {
		t.Fatalf("protocolLabel(easyconnect) = %q", got)
	}
}

// ---- app-level share wiring ------------------------------------------------

// appTestSource is a Source that authorizes one range and dials a local echo
// endpoint, so the app-level wiring can be exercised without a VPN.
type appTestSource struct {
	echo   string
	done   chan struct{}
	closed sync.Once
	snap   relay.SourceSnapshot
}

func newAppTestSource(echo string) *appTestSource {
	res := &relay.ResourceSnapshot{
		IPRules: []relay.IPRule{{Min: "10.5.0.0", Max: "10.5.255.255", PortMin: 443, PortMax: 443, Protocol: "tcp"}},
	}
	res.Normalize()
	caps := relay.Capabilities{StrictTCP: true}
	return &appTestSource{
		echo: echo,
		done: make(chan struct{}),
		snap: relay.SourceSnapshot{Epoch: 1, Revision: res.Revision(caps), Resources: res, Capabilities: caps},
	}
}

func (s *appTestSource) Snapshot(context.Context) (relay.SourceSnapshot, error) {
	return s.snap, nil
}

func (s *appTestSource) DialVPN(ctx context.Context, revision, target string) (net.Conn, error) {
	return net.Dial("tcp", s.echo)
}

func (s *appTestSource) ExchangeDNS(context.Context, string, []byte) ([]byte, error) {
	return nil, relay.NewError(relay.CodeProtocolUnsupported, "not supported")
}

func (s *appTestSource) Changes() <-chan struct{} { return make(chan struct{}) }
func (s *appTestSource) Done() <-chan struct{}    { return s.done }
func (s *appTestSource) Close() error {
	s.closed.Do(func() { close(s.done) })
	return nil
}

// appTestSink binds every point to a fresh source.
type appTestSink struct {
	mu    sync.Mutex
	names map[string]string
	echo  string
}

func (s *appTestSink) AcquireSource(ctx context.Context, id string) (relay.Source, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.names[id]; !ok {
		return nil, relay.ErrPointMissing
	}
	return newAppTestSource(s.echo), nil
}

func (s *appTestSink) PointName(id string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.names[id]
}

func (s *appTestSink) PointExists(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.names[id]
	return ok
}

func installLANShare(t *testing.T, a *app, sink relay.Sink) *relay.Controller {
	t.Helper()
	ctrl := relay.NewController(store.RelayShareStore{Store: a.store}, sink, emptyNets{}, nil, a.invalidate)
	a.lanShare = ctrl
	a.lanShareUI.results = make(chan lanShareResult, 4)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = ctrl.Shutdown(ctx)
	})
	return ctrl
}

// reopenAppWithSink builds a second app over the same data directory and secret
// store, which is what an application restart is.
func reopenAppWithSink(t *testing.T, dir string, sink relay.Sink) *app {
	t.Helper()
	secrets, err := store.NewFileSecrets(dir)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dir, secrets)
	if err != nil {
		t.Fatal(err)
	}
	a := &app{store: st, dir: dir, bus: vpn.NewLogBus(50), icon: loadAppIcon()}
	a.cfg = st.Config()
	a.mgr = vpn.NewManager(
		func(context.Context, model.AccessPoint, vpn.Credentials) (vpn.Session, error) {
			return stubSession{ip: "10.10.1.23"}, nil
		},
		a.credentials, a.bus, a.invalidate,
	)
	t.Cleanup(a.mgr.Close)
	a.mgr.Apply(a.cfg)
	a.loadRelayKnown()
	installLANShare(t, a, sink)
	return a
}

func waitAppShare(t *testing.T, a *app, want relay.State) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if a.lanShare.View().State == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("share state = %s, want %s (%+v)", a.lanShare.View().State, want, a.lanShare.View())
}

// TestAppShareSurvivesRestartThroughAppWiring exercises the exact production
// hooks (setupLANShare/loadRelayKnown/resumeLANShare/shutdownLANShare): enable →
// shutdown → restart → same code → shutdown again → still restored → disable →
// restart stays off.
func TestAppShareSurvivesRestartThroughAppWiring(t *testing.T) {
	a := testApp(t)
	if _, err := a.store.Update(func(cfg *model.Config) error {
		cfg.Add(model.AccessPoint{ID: "a1", Name: "公司 VPN", Protocol: model.ProtocolATrust, Server: "vpn.example.com", Port: 443, Username: "u", InPool: true})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	a.setConfig(a.store.Config())
	a.mgr.Apply(a.cfg)
	echo, closeEcho := echoListenerForTest(t)
	defer closeEcho()
	sink := &appTestSink{names: map[string]string{"a1": "公司 VPN"}, echo: echo}
	ctrl := installLANShare(t, a, sink)

	ctx := context.Background()
	if err := ctrl.Enable(ctx, relay.EnableOptions{PointID: "a1", PreferredIPv4: "127.0.0.1"}); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	codeBefore, err := ctrl.ShareCode()
	if err != nil {
		t.Fatal(err)
	}
	a.shutdownLANShare()

	b := reopenAppWithSink(t, a.store.Dir(), sink)
	if !b.cfg.Settings.LANShare.Enabled {
		t.Fatal("the enable intent did not survive the restart")
	}
	b.resumeLANShare()
	waitAppShare(t, b, relay.StateRunning)
	codeAfter, err := b.lanShare.ShareCode()
	if err != nil {
		t.Fatal(err)
	}
	if codeAfter != codeBefore {
		t.Fatalf("app restart changed the share code:\n%s\n%s", codeBefore, codeAfter)
	}
	b.shutdownLANShare()

	// A share that is still enabled keeps resuming on further starts.
	c := reopenAppWithSink(t, a.store.Dir(), sink)
	c.resumeLANShare()
	waitAppShare(t, c, relay.StateRunning)

	// 关闭共享 then restart: off, no listener, no code.
	if err := c.lanShare.Disable(ctx); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	c.shutdownLANShare()
	d := reopenAppWithSink(t, a.store.Dir(), sink)
	if d.cfg.Settings.LANShare.Enabled {
		t.Fatal("the disabled state did not survive the restart")
	}
	d.resumeLANShare()
	time.Sleep(150 * time.Millisecond)
	if view := d.lanShare.View(); view.State != relay.StateOff || view.Enabled {
		t.Fatalf("a disabled share came back: %+v", view)
	}
	if _, err := d.lanShare.ShareCode(); err == nil {
		t.Fatal("a disabled share still exposes a code")
	}
}

// echoListenerForTest runs a loopback echo endpoint for the app-level share test.
func echoListenerForTest(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

// S1: the relay snapshot hook runs on a connection goroutine. It used to call
// setConfig, replacing the UI-thread configuration while a render pass read it
// (pointLabel and every other accessor take no lock). This is the review's
// reproducer, kept as a regression under -race.
func TestRelaySnapshotNeverWritesUIConfig(t *testing.T) {
	a := testApp(t)
	point := model.AccessPoint{
		ID: "review-relay", Name: "review relay", Protocol: model.ProtocolLANRelay,
		Server: "192.168.1.50", Port: 23456, InPool: true,
		Relay: &model.RelayPointOptions{
			Version:           1,
			ShareID:           base64.RawURLEncoding.EncodeToString([]byte("aaaaaaaaaaaaaaaa")),
			CertificateSHA256: strings.Repeat("ab", 32),
		},
	}
	if _, err := a.store.Update(func(cfg *model.Config) error {
		cfg.Add(point)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	a.setConfig(a.store.Config())
	a.mgr.Apply(a.cfg)
	resources := &workeripc.ResourceSnapshot{
		Tunnel:  "ipv4-l3",
		IPRules: []workeripc.IPRule{{Min: "10.5.0.0", Max: "10.5.255.255", PortMin: 443, PortMax: 443, Protocol: "tcp"}},
	}
	ident := vpn.RelaySnapshotSource{ShareID: point.Relay.ShareID, Fingerprint: point.Relay.CertificateSHA256}
	done := make(chan error, 1)
	go func() { done <- a.saveRelaySnapshot(point.ID, ident, resources) }()
	for {
		// The real UI path: rendering a point label reads the configuration.
		if got := a.pointLabel(point.ID); got != point.Name {
			t.Fatalf("unexpected UI point name %q", got)
		}
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
			// Only the UI thread publishes; the hook must not have done it.
			if p := a.cfg.Points[0]; p.Relay != nil && p.Relay.HistoryInitialized {
				t.Fatal("the background hook published the marker itself")
			}
			a.applyPendingConfigReload()
			if p := a.cfg.Points[0]; p.Relay == nil || !p.Relay.HistoryInitialized {
				t.Fatal("the UI reload did not pick up the persisted marker")
			}
			return
		default:
		}
	}
}

// S1: a queued reload must not roll back an edit saved after the notification,
// because the UI thread re-reads the Store instead of accepting a captured copy.
func TestPendingConfigReloadKeepsNewerEdits(t *testing.T) {
	a := testApp(t)
	if _, err := a.store.Update(func(cfg *model.Config) error {
		cfg.Add(model.AccessPoint{ID: "p1", Name: "编辑前", Protocol: model.ProtocolATrust, Server: "vpn.example.com", Port: 443, Username: "u", InPool: true})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	a.setConfig(a.store.Config())
	// Background work finishes and asks for a reload...
	a.requestConfigReload()
	// ...but the user saves an edit before the next frame.
	if _, err := a.store.Update(func(cfg *model.Config) error {
		if p := cfg.Find("p1"); p != nil {
			p.Name = "编辑后"
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := a.store.Save(); err != nil {
		t.Fatal(err)
	}
	a.applyPendingConfigReload()
	if got := a.pointLabel("p1"); got != "编辑后" {
		t.Fatalf("UI config after reload = %q, want the newer edit", got)
	}
	if a.cfgReload.Load() {
		t.Fatal("the reload flag was not consumed")
	}
}
