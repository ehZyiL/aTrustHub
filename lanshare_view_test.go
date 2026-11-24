package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/egoist/mygo/ui"

	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/ehzyil/connect-hub/internal/relay"
	"github.com/ehzyil/connect-hub/internal/store"
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
