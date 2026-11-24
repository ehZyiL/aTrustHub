package main

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/egoist/mygo/ui"

	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/ehzyil/connect-hub/internal/relay"
	"github.com/ehzyil/connect-hub/internal/relay/discovery"
)

// lanDiscovery owns the two sides of 局域网发现: the publisher that follows the
// share lifecycle, and the browser that only lives while the page is open.
//
// Nothing here runs on the render loop for correctness: the publisher is woken
// by controller notifications through kick, and the browser is started and
// stopped by the UI thread because it is a user action.
type lanDiscovery struct {
	backend discovery.Backend
	pub     *discovery.Publisher
	browser *discovery.Browser

	kick     chan struct{}
	stop     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup

	// suppressed stops announcements for this run without touching the
	// preference. It is used when the user turns discovery off and the saved
	// preference could not be written: the network stops now, the disk catches
	// up later.
	mu         sync.Mutex
	suppressed bool
	shutDown   bool
	pending    *discovery.Snapshot
	lastErr    string

	// ui is UI-thread only.
	ui lanDiscoveryUI
}

// lanDiscoveryUI is the 发现局域网分享 page state. It holds no credential: a
// candidate is an address and a name, never an authorization.
type lanDiscoveryUI struct {
	open bool
	// tab is 0 for discovery and 1 for pasting a share code.
	tab       int
	ifaceName string
	busy      bool
	err       string
	snap      discovery.Snapshot
	cands     []discovery.Candidate
	notice    string
	// searching is true during the first seconds of a browse: an empty list
	// then means "still looking", not "there is nothing".
	searching bool
	startedAt time.Time
	// searchWindow is how long an empty list reads as "still looking". It is a
	// variable so tests can shorten it.
	searchWindow time.Duration
}

// setupLANDiscovery builds the publisher and the browser. The browser emits
// snapshots from its own goroutine, so they are parked here and picked up by
// the UI thread on its next frame.
func (a *app) setupLANDiscovery() {
	backend := a.discoveryBackend
	if backend == nil {
		backend = discovery.NewMDNSBackend(func(format string, args ...any) {
			a.tunLogf("局域网发现："+format, args...)
		})
	}
	d := &lanDiscovery{
		backend: backend,
		kick:    make(chan struct{}, 1),
		stop:    make(chan struct{}),
	}
	d.pub = discovery.NewPublisher(discovery.PublisherOptions{
		Backend: backend,
		Logf: func(format string, args ...any) {
			a.tunLogf("局域网发现："+format, args...)
		},
		OnChange: func(discovery.Status) {
			a.invalidateCoalesced()
		},
	})
	d.browser = discovery.NewBrowser(discovery.BrowserOptions{
		Backend: backend,
		Logf: func(format string, args ...any) {
			a.tunLogf("局域网发现："+format, args...)
		},
		Emit: func(s discovery.Snapshot) {
			d.mu.Lock()
			snapshot := s
			d.pending = &snapshot
			d.mu.Unlock()
			a.invalidateCoalesced()
		},
	})
	a.lanDisc = d

	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		// A slow tick is only a safety net: every real change kicks the loop.
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-d.stop:
				return
			case <-d.kick:
			case <-ticker.C:
				// A frame at least every two seconds keeps the time-based UI
				// state (the first-seconds "searching" text) from going stale.
				a.invalidateCoalesced()
			}
			a.syncLANDiscovery()
		}
	}()
}

// resumeLANDiscovery runs after the share restored: a share that is already
// running re-announces itself, a waiting one stays quiet.
func (a *app) resumeLANDiscovery() {
	a.kickLANDiscovery()
}

// shutdownLANDiscovery withdraws the announcement before the listener closes,
// then stops browsing. It never blocks quitting for long: a lost goodbye only
// costs colleagues the TTL.
func (a *app) shutdownLANDiscovery() {
	d := a.lanDisc
	if d == nil {
		return
	}
	d.stopOnce.Do(func() {
		d.mu.Lock()
		d.shutDown = true
		d.mu.Unlock()
		close(d.stop)
	})
	d.wg.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	_ = d.pub.Close(ctx)
	cancel()
	_ = d.browser.Close()
}

func (a *app) kickLANDiscovery() {
	if a.lanDisc == nil {
		return
	}
	select {
	case a.lanDisc.kick <- struct{}{}:
	default:
	}
}

// syncLANDiscovery publishes exactly the announcement the controller allows, or
// nothing. It is the only place that decides, so the state matrix has one
// implementation.
func (a *app) syncLANDiscovery() {
	d := a.lanDisc
	if d == nil || a.lanShare == nil {
		return
	}
	d.mu.Lock()
	suppressed := d.suppressed
	d.mu.Unlock()
	if suppressed {
		d.pub.Clear()
		return
	}
	view, ok := a.lanShare.DiscoverySnapshot()
	if !ok {
		d.pub.Clear()
		return
	}
	name := view.Name
	if strings.TrimSpace(name) == "" {
		name = model.DefaultDiscoveryName(view.ShareID)
	}
	ann := discovery.Announcement{
		Generation:      view.Generation,
		ShareID:         view.ShareID,
		Name:            name,
		ProtocolVersion: view.ProtocolVersion,
		Interface: discovery.Interface{
			Name: view.InterfaceName,
			IPv4: view.Address,
		},
		Address: view.Address,
		Port:    view.Port,
	}
	if err := ann.Validate(); err != nil {
		// A share that cannot be described correctly is not announced at all.
		a.tunLogf("局域网发现：公告不可用：%v", err)
		d.pub.Clear()
		return
	}
	d.pub.Set(ann)
}

// discoveryStatus is what the host panel shows.
func (a *app) discoveryStatus() discovery.Status {
	if a.lanDisc == nil {
		return discovery.Status{State: discovery.StatusIdle}
	}
	return a.lanDisc.pub.Status()
}

// setLANDiscoveryPreference is the host switch. Turning discovery on saves the
// preference first and only then announces; turning it off stops the network
// immediately and then saves, so a failed save cannot leave a share broadcasting
// after the user said stop.
func (a *app) setLANDiscoveryPreference(enabled bool, name string) error {
	d := a.lanDisc
	if d == nil || a.lanShare == nil {
		return fmt.Errorf("发现尚未初始化")
	}
	name = strings.TrimSpace(name)
	if name != "" {
		if err := model.ValidDiscoveryName(name); err != nil {
			return err
		}
	}
	if enabled {
		if err := a.lanShare.SetDiscovery(true, name); err != nil {
			return err
		}
		d.mu.Lock()
		d.suppressed = false
		d.mu.Unlock()
		a.kickLANDiscovery()
		return nil
	}
	d.mu.Lock()
	d.suppressed = true
	d.mu.Unlock()
	d.pub.Clear()
	if err := a.lanShare.SetDiscovery(false, name); err != nil {
		return fmt.Errorf("发现已停止，但偏好未保存：%w", err)
	}
	return nil
}

// retryLANDiscoveryPreference re-attempts the save after a failed switch-off.
func (a *app) retryLANDiscoveryPreference() error {
	d := a.lanDisc
	if d == nil || a.lanShare == nil {
		return fmt.Errorf("发现尚未初始化")
	}
	// The retry only re-attempts the write; the public name the user chose
	// must survive it.
	name := a.lanShare.Settings().DiscoveryName
	if err := a.lanShare.SetDiscovery(false, name); err != nil {
		return err
	}
	d.mu.Lock()
	d.suppressed = false
	d.mu.Unlock()
	a.kickLANDiscovery()
	return nil
}

// ---- browsing ------------------------------------------------------------

// browseInterfaces returns the exact interfaces to browse on. Virtual adapters
// and point-to-point links are not browsing targets by default: they are what
// makes "I found my own VPN" a bug report.
func (a *app) browseInterfaces(choice string) []discovery.Interface {
	var source []relay.Interface
	if a.lanShare != nil {
		source = lanAddresses{}.LANCandidates()
	}
	seen := make(map[string]bool)
	var out []discovery.Interface
	for _, cand := range source {
		if cand.IPv4 == "" || seen[cand.Name+"|"+cand.IPv4] {
			continue
		}
		if virtualInterface(cand.Name) {
			continue
		}
		if choice != "" && cand.Name != choice {
			continue
		}
		seen[cand.Name+"|"+cand.IPv4] = true
		out = append(out, discovery.Interface{Name: cand.Name, IPv4: cand.IPv4})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].IPv4 < out[j].IPv4
	})
	if len(out) > 4 {
		out = out[:4]
	}
	return out
}

// openLANDiscovery is called by the UI when the discovery tab becomes visible.
func (a *app) openLANDiscovery() {
	d := a.lanDisc
	if d == nil || a.lanDiscoveryShutDown() {
		return
	}
	d.ui.open = true
	a.startLANDiscoveryBrowsing()
}

// closeLANDiscovery stops browsing. A closed page must never keep a socket, a
// timer or a callback alive.
func (a *app) closeLANDiscovery() {
	d := a.lanDisc
	if d == nil {
		return
	}
	d.ui.open = false
	d.ui.searching = false
	d.ui.cands = nil
	_ = d.browser.Close()
}

func (a *app) startLANDiscoveryBrowsing() {
	d := a.lanDisc
	if d == nil || a.lanDiscoveryShutDown() {
		return
	}
	ifaces := a.browseInterfaces(d.ui.ifaceName)
	d.ui.busy = true
	d.ui.err = ""
	d.ui.notice = ""
	d.ui.cands = nil
	d.ui.snap = discovery.Snapshot{}
	d.ui.searching = true
	d.ui.startedAt = time.Now()
	if err := d.browser.Start(ifaces); err != nil {
		d.ui.err = err.Error()
	}
	d.ui.busy = false
	a.invalidate()
}

// refreshLANDiscovery re-queries the same generation without losing results.
func (a *app) refreshLANDiscovery() {
	d := a.lanDisc
	if d == nil {
		return
	}
	if err := d.browser.Refresh(); err != nil {
		d.ui.err = err.Error()
	}
	a.invalidate()
}

// setLANDiscoveryInterface switches the browsing network. A new network means a
// new generation: entries from the old interface must not survive it.
func (a *app) setLANDiscoveryInterface(name string) {
	d := a.lanDisc
	if d == nil {
		return
	}
	if d.ui.ifaceName == name {
		return
	}
	d.ui.ifaceName = name
	a.startLANDiscoveryBrowsing()
}

// drainLANDiscovery moves a background snapshot onto the UI thread. It is the
// only writer of the list, which keeps the UI free of locking.
func (a *app) drainLANDiscovery() {
	d := a.lanDisc
	if d == nil || !d.ui.open {
		return
	}
	d.mu.Lock()
	snap := d.pending
	d.pending = nil
	d.mu.Unlock()
	if snap != nil && (d.ui.snap.Generation == 0 || snap.Generation >= d.ui.snap.Generation) {
		// A snapshot from an older generation must not overwrite a newer list.
		d.ui.snap = *snap
		d.ui.cands = a.withoutOwnShare(snap.Candidates)
	}
	// The "still looking" flag is time-based, so it is recomputed on every frame
	// instead of only when a snapshot arrives.
	window := d.ui.searchWindow
	if window <= 0 {
		window = 5 * time.Second
	}
	d.ui.searching = len(d.ui.cands) == 0 && time.Since(d.ui.startedAt) < window
}

// ---- host panel ----------------------------------------------------------

// lanShareDiscoveryView is the discovery block of the 局域网分享 panel. It only
// edits the preference: switching it never restarts the share, revokes the
// token or touches the access point.
func (a *app) lanShareDiscoveryView(c *ui.Context, view relay.View) {
	t := c.Theme()
	d := &a.lanShareUI
	status := a.discoveryStatus()
	name := view.DiscoveryName
	if strings.TrimSpace(name) == "" {
		shareID := ""
		if a.lanShare != nil {
			shareID = a.lanShare.Settings().ShareID
		}
		name = model.DefaultDiscoveryName(shareID)
	}

	label, color := discoveryStatusText(t, view, status)
	ui.Column(c).Gap(5).Children(func() {
		ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
			ui.Text(c, "局域网发现").FontSize(12).TextColor(t.TextMuted).Width(110)
			ui.Text(c, label).FontSize(12).TextColor(color).Wrap()
			ui.Row(c).Grow(1)
			button := "允许被发现"
			if view.DiscoveryEnabled {
				button = "停止被发现"
			}
			if ui.Button(c, button).FontSize(11).Disabled(d.discoveryBusy || !view.Enabled).Clicked() {
				a.toggleLANDiscovery(!view.DiscoveryEnabled)
			}
		})
		ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
			ui.Text(c, "公开名称").FontSize(12).TextColor(t.TextMuted).Width(110)
			if d.discoveryEditing {
				ui.TextInput(c, &d.discoveryName).Width(240)
				if ui.Button(c, "保存名称").FontSize(11).Disabled(d.discoveryBusy).Clicked() {
					a.saveLANDiscoveryName(d.discoveryName)
				}
				if ui.Button(c, "取消").FontSize(11).Clicked() {
					d.discoveryEditing = false
					d.discoveryName = view.DiscoveryName
				}
			} else {
				ui.Text(c, name).FontSize(12).Wrap()
				ui.Row(c).Grow(1)
				if ui.Button(c, "改名").FontSize(11).Disabled(d.discoveryBusy || !view.Enabled).Clicked() {
					d.discoveryEditing = true
					d.discoveryName = view.DiscoveryName
				}
			}
		})
		ui.Text(c, "同一网络的其他设备可以看到该名称和连接地址；加入仍需分享口令。发现不会开启共享、VPN 或系统代理。").
			FontSize(11).TextColor(t.TextMuted).Wrap()
		if status.State == discovery.StatusFailed {
			ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
				ui.Text(c, "发现不可用："+status.Message+"（分享仍在运行，可以使用口令）").
					FontSize(11).TextColor(t.Warning).Wrap()
				ui.Row(c).Grow(1)
				if ui.Button(c, "重试发现").FontSize(11).Clicked() {
					a.kickLANDiscovery()
				}
			})
		}
	})
}

// discoveryStatusText maps the publisher state to the panel's wording. "已发布"
// never claims that a colleague received or reached the share.
func discoveryStatusText(t *ui.Theme, view relay.View, status discovery.Status) (string, ui.Color) {
	switch status.State {
	case discovery.StatusPublished:
		return "正在发布（已注册，不代表同事已收到）", t.Success
	case discovery.StatusPending:
		return "正在发布…", t.TextMuted
	case discovery.StatusFailed:
		return "发现不可用", t.Warning
	}
	if view.DiscoveryEnabled {
		if view.State == relay.StateRunning {
			return "等待发布", t.TextMuted
		}
		return "等待共享可用", t.Warning
	}
	return "未允许发现", t.TextMuted
}

func (a *app) toggleLANDiscovery(on bool) {
	d := &a.lanShareUI
	name := d.discoveryName
	d.discoveryBusy = true
	d.err, d.notice = "", ""
	go func() {
		err := a.setLANDiscoveryPreference(on, name)
		notice := ""
		if err == nil && on {
			notice = "已允许同一网络的同事发现这条分享。"
		}
		if err == nil && !on {
			notice = "已停止被发现；分享和口令继续有效。"
		}
		a.postLANShareResult(lanShareResult{action: "discovery", err: err, notice: notice})
	}()
	a.invalidate()
}

func (a *app) saveLANDiscoveryName(name string) {
	d := &a.lanShareUI
	d.discoveryBusy = true
	d.err, d.notice = "", ""
	go func() {
		err := a.setLANDiscoveryPreference(true, name)
		a.postLANShareResult(lanShareResult{action: "discovery-name", err: err, notice: "公开名称已更新"})
	}()
	a.invalidate()
}

// ---- colleague side ------------------------------------------------------

// relayDiscoveryBody is the 发现局域网分享 list. It shows only what was learned
// from the network: a name, an address and a port. Joining still needs a code.
func (a *app) relayDiscoveryBody(c *ui.Context, d *relayImportDraft) {
	t := c.Theme()
	disc := a.lanDisc
	if disc == nil {
		ui.Text(c, "发现未启用，请粘贴分享口令加入。").FontSize(12).TextColor(t.TextMuted).Wrap()
		return
	}
	ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
		ui.Text(c, "使用网络").FontSize(12).TextColor(t.TextMuted)
		labels, byLabel := a.discoveryInterfaceChoices()
		current := "自动选择"
		for label, name := range byLabel {
			if name == disc.ui.ifaceName {
				current = label
			}
		}
		next := current
		if next == "自动选择" {
			next = "自动选择"
		}
		all := append([]string{"自动选择"}, labels...)
		if ui.Select(c, &next, all).Width(220).Changed() {
			a.setLANDiscoveryInterface(byLabel[next])
		}
		ui.Row(c).Grow(1)
		if ui.Button(c, "刷新").FontSize(11).Clicked() {
			a.refreshLANDiscovery()
		}
	})
	ui.Text(c, "只浏览当前网卡；发现不会发起连接，也不会读取已保存的凭据。").
		FontSize(11).TextColor(t.TextMuted).Wrap()

	if disc.ui.err != "" {
		ui.Column(c).Gap(3).Children(func() {
			ui.Text(c, disc.ui.err).FontSize(11).TextColor(t.Warning).Wrap()
			ui.Text(c, "仍然可以粘贴分享口令加入。").
				FontSize(11).TextColor(t.TextMuted).Wrap()
		})
	}
	if len(disc.ui.cands) == 0 {
		// The first seconds must not claim "nothing there": multicast answers
		// take a moment, and a premature empty state reads as "it is broken".
		if disc.ui.searching {
			ui.Text(c, "正在查找局域网分享…").FontSize(12).TextColor(t.TextMuted)
		} else {
			ui.Text(c, "暂未发现分享。请确认主机已开启共享并允许被发现；也可以粘贴分享口令。").
				FontSize(11).TextColor(t.TextMuted).Wrap()
		}
		return
	}
	for _, cand := range disc.ui.cands {
		cand := cand
		ui.Column(c).Key("disc:"+cand.Key()).Padding(8, 10).Gap(3).Radius(8).
			Border(1, t.Border).Children(func() {
			ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
				name := cand.Name
				if name == "" {
					name = "未命名分享"
				}
				ui.Text(c, name).FontSize(13).Bold().Wrap()
				ui.Row(c).Grow(1)
				a.relayDiscoveryAction(c, d, cand)
			})
			ui.Text(c, cand.Address+":"+strconv.Itoa(cand.Port)+" · "+cand.Interface).
				FontSize(11).TextColor(t.TextMuted)
			if !cand.Compatible() {
				ui.Text(c, "分享协议暂不兼容，请核对双方版本。").FontSize(11).TextColor(t.Warning)
			}
		})
	}
}

// relayDiscoveryAction renders 加入 / 已导入 / 地址不同 for one candidate.
func (a *app) relayDiscoveryAction(c *ui.Context, d *relayImportDraft, cand discovery.Candidate) {
	t := c.Theme()
	if existing, sameEndpoint := a.findRelayPointByShareID(cand); existing != nil {
		if sameEndpoint {
			ui.Text(c, "已导入，待验证").FontSize(11).TextColor(t.TextMuted)
			if ui.Button(c, "连接").FontSize(11).Clicked() {
				a.closeRelayImport()
				go a.mgr.Connect(existing.ID)
				a.toast = "正在连接「" + existing.Name + "」"
			}
			return
		}
		ui.Text(c, "地址不同，需新口令核对").FontSize(11).TextColor(t.Warning)
		return
	}
	if ui.Button(c, "加入").FontSize(11).Disabled(!cand.Compatible()).Clicked() {
		d.pinned = cand
		d.pinnedKey = cand.Key()
		d.tab = 1
		d.err = ""
		a.closeLANDiscovery()
		a.invalidate()
	}
}

// discoveryInterfaceChoices lists the browsing networks. An empty name means
// automatic selection.
func (a *app) discoveryInterfaceChoices() ([]string, map[string]string) {
	var labels []string
	byLabel := map[string]string{}
	seen := map[string]bool{}
	for _, cand := range a.browseInterfaces("") {
		if seen[cand.Name] {
			continue
		}
		seen[cand.Name] = true
		label := cand.Name
		labels = append(labels, label)
		byLabel[label] = cand.Name
	}
	sort.Strings(labels)
	return labels, byLabel
}

// findRelayPointByShareID matches an already imported node by share ID and
// reports whether its saved endpoint equals the discovered one. A match is a
// convenience, never proof of identity: the saved fingerprint and credentials
// still decide the connection.
func (a *app) findRelayPointByShareID(cand discovery.Candidate) (*model.AccessPoint, bool) {
	for i := range a.cfg.Points {
		p := &a.cfg.Points[i]
		if p.Protocol != model.ProtocolLANRelay || p.Relay == nil || p.Relay.ShareID != cand.ShareID {
			continue
		}
		// Only an identical endpoint may reuse the saved node. A different
		// address is a different offer that needs a fresh code.
		return p, p.Server == cand.Address && p.Port == cand.Port
	}
	return nil, false
}

// discoveryNamePlaceholder is the example shown in the name field. It must be
// stable across frames: a random example would flicker on every render.
func (a *app) discoveryNamePlaceholder() string {
	shareID := ""
	if a.lanShare != nil {
		shareID = a.lanShare.Settings().ShareID
	}
	if shareID == "" {
		return "例如：会议室共享"
	}
	return model.DefaultDiscoveryName(shareID)
}

// lanDiscoveryShutDown reports whether the app has already stopped discovery.
// After that point a late page-open must not start browsing again: the sockets
// are gone and nothing would ever close them.
func (a *app) lanDiscoveryShutDown() bool {
	d := a.lanDisc
	if d == nil {
		return true
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.shutDown
}

// withoutOwnShare drops this machine's own announcement from the list. The test
// is address-based on purpose: a bare share ID is self-reported, so filtering on
// the ID alone would hide a real colleague who copied an identity.
func (a *app) withoutOwnShare(cands []discovery.Candidate) []discovery.Candidate {
	if a.lanShare == nil {
		return cands
	}
	own := a.lanShare.Settings()
	if !own.Enabled || own.ShareID == "" {
		return cands
	}
	local := make(map[string]bool)
	for _, cand := range (lanAddresses{}).LANCandidates() {
		local[cand.IPv4] = true
	}
	out := make([]discovery.Candidate, 0, len(cands))
	for _, cand := range cands {
		if cand.ShareID == own.ShareID && local[cand.Address] {
			continue
		}
		out = append(out, cand)
	}
	return out
}
