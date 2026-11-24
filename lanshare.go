package main

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/egoist/mygo/ui"

	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/ehzyil/connect-hub/internal/relay"
	"github.com/ehzyil/connect-hub/internal/store"
	"github.com/ehzyil/connect-hub/internal/vpn"
	"github.com/ehzyil/connect-hub/internal/workeripc"
)

// lanShareResult is one finished async action. Results travel through a channel
// instead of being written from a worker goroutine, so the UI thread stays the
// only writer of the draft.
type lanShareResult struct {
	action string
	err    error
	notice string
}

// lanShareDraft is the 局域网分享 panel state. It holds no credential: the share
// code is read from the controller only while it is running.
type lanShareDraft struct {
	open bool
	// pointID is the single shared access point. There is no resource list.
	pointID       string
	interfaceName string
	ipv4          string
	portText      string
	advanced      bool
	busy          bool
	busyAction    string
	err           string
	notice        string
	confirmClose  bool
	showCode      bool
	results       chan lanShareResult
}

// relaySink binds the relay controller to the app's manager and configuration.
type relaySink struct{ a *app }

func (s relaySink) AcquireSource(ctx context.Context, pointID string) (relay.Source, error) {
	if s.a.mgr == nil {
		return nil, relay.ErrPointNotReady
	}
	return s.a.mgr.AcquireRelayShareSource(pointID)
}

func (s relaySink) PointName(pointID string) string {
	cfg := s.a.configForBackground()
	if p := cfg.Find(pointID); p != nil {
		return p.Name
	}
	return ""
}

func (s relaySink) PointExists(pointID string) bool {
	cfg := s.a.configForBackground()
	return cfg.Find(pointID) != nil
}

// lanAddresses enumerates the addresses a share may bind: up, non-loopback
// interfaces with a private IPv4 address. Interface names only order the list;
// they are never the sole test.
type lanAddresses struct{}

func (lanAddresses) LANCandidates() []relay.Interface {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []relay.Interface
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipnet.IP.To4()
			if ip == nil || !model.RFC1918(ip) {
				continue
			}
			out = append(out, relay.Interface{Name: iface.Name, IPv4: ip.String()})
		}
	}
	// Physical interfaces first: a docker bridge or a VPN adapter is a poor
	// default for a colleague on the office Wi-Fi, but it is not refused.
	sort.SliceStable(out, func(i, j int) bool {
		return interfaceRank(out[i].Name) < interfaceRank(out[j].Name)
	})
	return out
}

func interfaceRank(name string) int {
	lower := strings.ToLower(name)
	for _, prefix := range []string{"docker", "veth", "br-", "virbr", "vmnet", "vboxnet", "utun", "tun", "tap", "lxc", "cni"} {
		if strings.HasPrefix(lower, prefix) {
			return 1
		}
	}
	return 0
}

// setupLANShare wires the controller. It runs after the manager exists, and it
// only prepares: Restore is what may resume a previously enabled share.
func (a *app) setupLANShare() {
	a.lanShare = relay.NewController(
		store.RelayShareStore{Store: a.store},
		relaySink{a: a},
		lanAddresses{},
		func(format string, args ...any) {
			if a.bus != nil {
				a.bus.Add("app", fmt.Sprintf(format, args...))
			}
		},
		a.invalidateCoalesced,
	)
	a.lanShareUI.results = make(chan lanShareResult, 4)
}

// resumeLANShare runs after the configuration and credentials are loaded. A
// share that was switched off stays off; one that was on waits for its access
// point instead of logging in anything by itself.
func (a *app) resumeLANShare() {
	if a.lanShare == nil {
		return
	}
	if err := a.lanShare.Restore(context.Background()); err != nil {
		a.tunLogf("局域网分享恢复：%v", err)
	}
}

// shutdownLANShare stops serving but keeps the enable intent, so the next start
// resumes it.
func (a *app) shutdownLANShare() {
	if a.lanShare == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = a.lanShare.Shutdown(ctx)
}

// lanShareEnabled reports whether the share intent is on.
func (a *app) lanShareEnabled() bool {
	return a.lanShare != nil && a.lanShare.View().Enabled
}

// ---- UI ------------------------------------------------------------------

// lanShareStrip is the compact status line under the toolbar. It only appears
// while sharing is enabled, so it costs no room when the feature is unused.
func (a *app) lanShareStrip(c *ui.Context) {
	if a.lanShare == nil {
		return
	}
	view := a.lanShare.View()
	if !view.Enabled {
		return
	}
	t := c.Theme()
	color := t.TextMuted
	text := "局域网分享已开启"
	switch view.State {
	case relay.StateRunning:
		text = "局域网分享已开启"
		if view.Clients > 0 {
			text = fmt.Sprintf("局域网分享已开启 · 活跃客户端 %d", view.Clients)
		}
		color = t.Success
	case relay.StateWaiting:
		text = "局域网分享：等待接入点连接"
		color = t.Warning
	case relay.StateBlocked:
		text = "局域网分享：暂未运行，需处理"
		color = t.Danger
	case relay.StateStarting:
		text = "局域网分享：正在开启…"
	}
	ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
		ui.Text(c, "●").FontSize(10).TextColor(color)
		ui.Text(c, text).FontSize(12).TextColor(color)
		ui.Row(c).Grow(1)
		if ui.Button(c, "管理").Label("管理局域网分享").FontSize(11).Clicked() {
			a.openLANShare()
		}
	})
}

// lanShareSection is the settings group. It is reachable in both simple and
// professional mode: sharing is not an advanced-only feature.
func (a *app) lanShareSection(c *ui.Context) {
	t := c.Theme()
	settingsGroup(c, "局域网分享", func() {
		if a.lanShare == nil {
			ui.Text(c, "局域网分享尚未初始化").FontSize(12).TextColor(t.TextMuted)
			return
		}
		view := a.lanShare.View()
		ui.Text(c, lanShareStateText(view)).FontSize(12).TextColor(lanShareStateColor(t, view)).Wrap()
		ui.Text(c, "把整个接入点的已授权资源分享给同一局域网的同事；未受管的公网目标使用同事自己的网络。").
			FontSize(11).TextColor(t.TextMuted).Wrap()
		if view.Enabled {
			ui.Row(c).Gap(8).Children(func() {
				if ui.Button(c, "管理共享").FontSize(11).Clicked() {
					a.openLANShare()
				}
				if ui.Button(c, "关闭共享").FontSize(11).Clicked() {
					a.openLANShare()
					a.lanShareUI.confirmClose = view.Clients > 0
					if !a.lanShareUI.confirmClose {
						a.disableLANShare()
					}
				}
			})
			return
		}
		ui.Row(c).Gap(8).Children(func() {
			if ui.PrimaryButton(c, "开启共享…").FontSize(11).Clicked() {
				a.openLANShare()
			}
			if ui.Button(c, "导入同事分享…").FontSize(11).Clicked() {
				a.openRelayImport()
			}
		})
	})
}

func lanShareStateText(view relay.View) string {
	switch view.State {
	case relay.StateRunning:
		if view.Clients > 0 {
			return fmt.Sprintf("分享已开启 · 活跃客户端 %d（%s:%d）", view.Clients, view.Address, view.Port)
		}
		return fmt.Sprintf("分享已开启 · 等待同事连接（%s:%d）", view.Address, view.Port)
	case relay.StateStarting:
		return "正在开启共享…"
	case relay.StateWaiting:
		if view.Failure != "" {
			return "共享已启用，" + view.Failure
		}
		return "共享已启用，等待接入点连接"
	case relay.StateBlocked:
		if view.Failure != "" {
			return "共享已启用，暂未运行：" + view.Failure
		}
		return "共享已启用，暂未运行"
	case relay.StateStopping, relay.StateCleanupPending:
		return "正在停止共享…"
	default:
		return "未开启局域网分享"
	}
}

func lanShareStateColor(t *ui.Theme, view relay.View) ui.Color {
	switch view.State {
	case relay.StateRunning:
		return t.Success
	case relay.StateWaiting, relay.StateStarting, relay.StateStopping, relay.StateCleanupPending:
		return t.Warning
	case relay.StateBlocked:
		return t.Danger
	}
	return t.TextMuted
}

// openLANShare prepares the panel from the real controller state. Opening it
// never starts a listener.
func (a *app) openLANShare() {
	d := &a.lanShareUI
	d.open = true
	d.err, d.notice = "", ""
	d.confirmClose = false
	d.showCode = false
	d.advanced = false
	d.portText = ""
	d.busy = false
	if d.results == nil {
		d.results = make(chan lanShareResult, 4)
	}
	if a.lanShare == nil {
		d.err = "局域网分享尚未初始化"
		return
	}
	settings := a.lanShare.Settings()
	d.pointID = settings.PointID
	d.interfaceName = settings.InterfaceName
	d.ipv4 = settings.PreferredIPv4
	if settings.Port != 0 {
		d.portText = fmt.Sprint(settings.Port)
	}
	if d.pointID == "" {
		// Default to the access point currently in use, but never select a
		// relay node: sharing a relay would loop. When nothing is online yet
		// the first shareable point is preselected, because choosing an
		// offline point legitimately means "enabled, waiting".
		for _, p := range a.cfg.Points {
			if p.Protocol == model.ProtocolLANRelay {
				continue
			}
			if v, ok := a.mgr.View(p.ID); ok && v.State == vpn.StateOnline {
				d.pointID = p.ID
				break
			}
		}
		if d.pointID == "" {
			for _, p := range a.cfg.Points {
				if p.Protocol == model.ProtocolLANRelay {
					continue
				}
				d.pointID = p.ID
				break
			}
		}
	}
	a.invalidate()
}

// shareablePoints lists the access points a share may bind.
func (a *app) shareablePoints() []vpn.View {
	var out []vpn.View
	for _, p := range a.cfg.Points {
		if p.Protocol == model.ProtocolLANRelay {
			continue
		}
		if v, ok := a.mgr.View(p.ID); ok {
			out = append(out, v)
		}
	}
	return out
}

func (a *app) pointLabel(id string) string {
	if p := a.cfg.Find(id); p != nil {
		return p.Name
	}
	return ""
}

// relayInterfaceChoices returns the label -> address mapping the panel offers.
func (a *app) relayInterfaceChoices() ([]string, map[string]relay.Interface) {
	list := lanAddresses{}.LANCandidates()
	labels := make([]string, 0, len(list))
	byLabel := make(map[string]relay.Interface, len(list))
	for _, cand := range list {
		label := fmt.Sprintf("%s · %s", cand.Name, cand.IPv4)
		labels = append(labels, label)
		byLabel[label] = cand
	}
	return labels, byLabel
}

func (a *app) lanShareView(c *ui.Context) {
	d := &a.lanShareUI
	if !d.open {
		return
	}
	a.drainLANShareResults()
	t := c.Theme()
	view := relay.View{}
	if a.lanShare != nil {
		view = a.lanShare.View()
	}
	ui.Modal(c, &d.open, func() {
		ui.Column(c).Width(dialogRegular).Gap(10).Children(func() {
			dialogHeader(c, "局域网分享", lanShareStateText(view))
			ui.Scroll(c).MaxHeight(a.dialogBodyMaxHeight()).MinHeight(0).
				ScrollbarInsets(4, 2, 4, 0).Children(func() {
				ui.Column(c).Padding(0, 14, 8, 0).Gap(10).Children(func() {
					ui.Text(c, "共享整个接入点，访问权限沿用该接入点；未受管公网使用同事自己的网络。").
						FontSize(12).TextColor(t.TextMuted).Wrap()
					ui.Text(c, "开启后记住状态，应用重启自动恢复；接入点未连接时等待。点击关闭共享后不再恢复。").
						FontSize(11).TextColor(t.TextMuted).Wrap()

					if !view.Enabled {
						a.lanShareEnableForm(c, d)
					} else {
						a.lanShareManageBody(c, d, view)
					}
					if d.notice != "" {
						ui.Text(c, d.notice).FontSize(11).TextColor(t.TextMuted).Wrap()
					}
					if d.err != "" {
						ui.Text(c, d.err).FontSize(11).TextColor(t.Danger).Wrap()
					}
					if d.confirmClose {
						ui.Text(c, fmt.Sprintf("将中断 %d 个活跃客户端的资源访问，当前口令立即失效，下次启动不再恢复。", view.Clients)).
							FontSize(12).TextColor(t.Danger).Wrap()
					}
				})
			})
			dialogFooter(c, func() {
				if ui.Button(c, "关闭面板").FontSize(11).Clicked() {
					d.open = false
				}
				ui.Row(c).Grow(1)
				if !view.Enabled {
					if d.busy {
						ui.Spinner(c)
					}
					if ui.PrimaryButton(c, "开启共享").FontSize(11).
						Disabled(d.busy || d.pointID == "").Clicked() {
						a.enableLANShare()
					}
					return
				}
				if ui.Button(c, "复制分享口令").FontSize(11).
					Disabled(view.State != relay.StateRunning).Clicked() {
					a.copyLANShareCode()
				}
				if ui.Button(c, "重试恢复").FontSize(11).Disabled(d.busy).Clicked() {
					a.retryLANShare()
				}
				if d.confirmClose {
					if ui.PrimaryButton(c, "确认关闭共享").FontSize(11).Background(t.Danger).
						TextColor(t.AccentText).Disabled(d.busy).Clicked() {
						a.disableLANShare()
					}
					return
				}
				if ui.Button(c, "关闭共享").FontSize(11).Disabled(d.busy).Clicked() {
					if view.Clients > 0 {
						d.confirmClose = true
						a.invalidate()
						return
					}
					a.disableLANShare()
				}
			})
		})
	})
	if !d.open {
		// Closing the panel keeps a running share running; it never cancels a
		// saved enable intent. Only dropping an in-flight first enable was a
		// cancellation, and that path is not entered from here.
		d.confirmClose = false
	}
}

func (a *app) lanShareEnableForm(c *ui.Context, d *lanShareDraft) {
	points := a.shareablePoints()
	labels := make([]string, 0, len(points))
	byLabel := map[string]vpn.View{}
	selected := ""
	for _, v := range points {
		label := v.Name
		if v.State != vpn.StateOnline {
			label += "（未登录）"
		}
		labels = append(labels, label)
		byLabel[label] = v
		if v.ID == d.pointID {
			selected = label
		}
	}
	if selected == "" && len(labels) > 0 {
		selected = labels[0]
		d.pointID = byLabel[selected].ID
	}
	ui.Field(c, "共享接入点", func() {
		if len(labels) == 0 {
			ui.Text(c, "还没有可分享的 VPN 接入点").FontSize(12).TextColor(c.Theme().TextMuted)
			return
		}
		next := selected
		if ui.Select(c, &next, labels).Width(320).Changed() {
			if v, ok := byLabel[next]; ok {
				d.pointID = v.ID
				a.invalidate()
			}
		}
	})
	ifa := d.interfaceName
	iaLabels, iaByLabel := a.relayInterfaceChoices()
	if len(iaLabels) > 0 {
		current := ""
		for label, cand := range iaByLabel {
			if cand.IPv4 == d.ipv4 || (d.ipv4 == "" && cand.Name == ifa) {
				current = label
			}
		}
		if current == "" {
			current = iaLabels[0]
			d.ipv4 = iaByLabel[current].IPv4
			d.interfaceName = iaByLabel[current].Name
		}
		ui.Field(c, "使用网络", func() {
			next := current
			if ui.Select(c, &next, iaLabels).Width(320).Changed() {
				cand := iaByLabel[next]
				d.ipv4, d.interfaceName = cand.IPv4, cand.Name
				a.invalidate()
			}
		})
	} else {
		ui.Text(c, "没有可用的局域网地址（需要已连接的 Wi-Fi 或有线网络）").
			FontSize(12).TextColor(c.Theme().Warning).Wrap()
	}
	ui.Checkbox(c, &d.advanced, "高级选项（固定端口）")
	if d.advanced {
		ui.Field(c, "监听端口", func() {
			ui.TextInput(c, &d.portText).Placeholder("留空自动分配").Width(140)
		})
	}
}

func (a *app) lanShareManageBody(c *ui.Context, d *lanShareDraft, view relay.View) {
	t := c.Theme()
	rows := [][2]string{
		{"共享接入点", orDash(view.PointName)},
		{"监听地址", orDash(view.Address)},
		{"端口", fmt.Sprint(orZero(view.Port))},
		{"运行状态", stateLabelOf(view.State)},
		{"重启后恢复", "是（点击关闭共享后不再恢复）"},
	}
	if !view.CertExpiry.IsZero() {
		rows = append(rows, [2]string{"证书有效期至", view.CertExpiry.Format("2006-01-02")})
	}
	for _, row := range rows {
		ui.Row(c).Gap(8).Children(func() {
			ui.Text(c, row[0]).FontSize(12).TextColor(t.TextMuted).Width(110)
			ui.Text(c, row[1]).FontSize(12).Wrap()
		})
	}
	if d.showCode {
		if code, err := a.lanShareCode(); err == nil {
			ui.Text(c, "分享口令（含访问权限，请通过可信渠道发送）：").FontSize(11).TextColor(t.TextMuted)
			ui.Text(c, code).Font("monospace").FontSize(10).Wrap()
		} else {
			ui.Text(c, "共享尚未运行，暂时没有可用的分享口令").FontSize(11).TextColor(t.TextMuted)
		}
	}
	ui.Row(c).Gap(8).Children(func() {
		if ui.Button(c, "显示分享口令").FontSize(11).Disabled(view.State != relay.StateRunning).Clicked() {
			d.showCode = !d.showCode
		}
		if ui.Button(c, "更换口令").Label("更换口令并断开现有连接").FontSize(11).Disabled(true).Clicked() {
		}
	})
	if view.State == relay.StateBlocked && view.Failure != "" {
		ui.Text(c, "原因："+view.Failure).FontSize(12).TextColor(t.Danger).Wrap()
	}
	if view.State == relay.StateRunning {
		info := relay.FirewallInfo()
		ui.Column(c).Gap(3).Children(func() {
			for _, line := range info.Lines {
				ui.Text(c, line).FontSize(11).TextColor(t.TextMuted).Wrap()
			}
			if info.Automatic {
				ui.Text(c, "本程序只在点击「允许局域网连接」并完成系统授权后修改防火墙，不会在开启共享时静默改规则。").
					FontSize(11).TextColor(t.TextMuted).Wrap()
			}
		})
		ui.Row(c).Gap(8).Children(func() {
			if ui.Button(c, "连接诊断").Label("分享状态检查").FontSize(11).Clicked() {
				a.openLANShareDiagnose()
			}
		})
	}
}

func orDash(v string) string {
	if strings.TrimSpace(v) == "" {
		return "—"
	}
	return v
}

func orZero(v int) int {
	if v <= 0 {
		return 0
	}
	return v
}

func stateLabelOf(s relay.State) string {
	switch s {
	case relay.StateRunning:
		return "分享已开启"
	case relay.StateStarting:
		return "正在开启"
	case relay.StateWaiting:
		return "等待接入点连接"
	case relay.StateBlocked:
		return "需要处理"
	case relay.StateStopping:
		return "正在停止"
	case relay.StateCleanupPending:
		return "关闭中，等待清理"
	default:
		return "未开启"
	}
}

func (a *app) lanShareCode() (string, error) {
	if a.lanShare == nil {
		return "", fmt.Errorf("局域网分享尚未初始化")
	}
	return a.lanShare.ShareCode()
}

// drainLANShareResults applies finished async actions on the UI thread.
func (a *app) drainLANShareResults() {
	d := &a.lanShareUI
	for {
		select {
		case res := <-d.results:
			d.busy = false
			d.busyAction = ""
			if res.err != nil {
				d.err = res.err.Error()
			} else if res.notice != "" {
				d.notice = res.notice
			}
			if res.action == "disable" && res.err == nil {
				d.open = false
			}
		default:
			return
		}
	}
}

func (a *app) postLANShareResult(res lanShareResult) {
	d := &a.lanShareUI
	if d.results == nil {
		d.results = make(chan lanShareResult, 4)
	}
	select {
	case d.results <- res:
	default:
	}
	a.invalidate()
}

func (a *app) enableLANShare() {
	d := &a.lanShareUI
	if a.lanShare == nil {
		d.err = "局域网分享尚未初始化"
		return
	}
	if d.pointID == "" {
		d.err = "请选择要共享的接入点"
		return
	}
	port := 0
	if d.advanced {
		text := strings.TrimSpace(d.portText)
		if text != "" {
			n, err := parsePort(text, "监听端口")
			if err != nil {
				d.err = err.Error()
				return
			}
			port = n
		}
	}
	opts := relay.EnableOptions{
		PointID:       d.pointID,
		InterfaceName: d.interfaceName,
		PreferredIPv4: d.ipv4,
		Port:          port,
	}
	d.busy, d.busyAction = true, "enable"
	d.err, d.notice = "", ""
	go func() {
		err := a.lanShare.Enable(context.Background(), opts)
		notice := "共享已开启。复制分享口令发给同事；应用重启后会自动恢复。"
		a.postLANShareResult(lanShareResult{action: "enable", err: err, notice: notice})
	}()
	a.invalidate()
}

func (a *app) disableLANShare() {
	d := &a.lanShareUI
	if a.lanShare == nil {
		return
	}
	d.busy, d.busyAction = true, "disable"
	d.err, d.notice = "", ""
	go func() {
		err := a.lanShare.Disable(context.Background())
		notice := ""
		if err == nil {
			notice = "共享已关闭，下次启动不再恢复。"
		}
		a.postLANShareResult(lanShareResult{action: "disable", err: err, notice: notice})
	}()
	a.invalidate()
}

func (a *app) retryLANShare() {
	d := &a.lanShareUI
	if a.lanShare == nil {
		return
	}
	d.busy, d.busyAction = true, "retry"
	d.err, d.notice = "", ""
	go func() {
		err := a.lanShare.Retry(context.Background())
		a.postLANShareResult(lanShareResult{action: "retry", err: err})
	}()
	a.invalidate()
}

func (a *app) copyLANShareCode() {
	code, err := a.lanShareCode()
	if err != nil {
		a.lanShareUI.err = err.Error()
		a.invalidate()
		return
	}
	a.copyText(code)
	a.lanShareUI.notice = "分享口令已复制"
	a.invalidate()
}

// saveRelaySnapshot is the relay connector's persistence hook. It runs before a
// snapshot may be announced as usable, so a crash right after going online still
// leaves the attribution behind: without it a known managed target could fall
// back to the original network on the next start.
func (a *app) saveRelaySnapshot(pointID string, resources *workeripc.ResourceSnapshot) error {
	if resources == nil {
		return nil
	}
	source := ""
	cfg := a.store.Config()
	if p := cfg.Find(pointID); p != nil && p.Relay != nil {
		source = p.Relay.CertificateSHA256 + "/" + p.Relay.ShareID
	}
	if err := a.store.SaveRelayKnown(pointID, source, resources); err != nil {
		// The protection gap must stay visible: the gate refuses unknown
		// targets instead of pretending the history is intact.
		if a.mgr != nil {
			a.mgr.SetRelayHistoryUnverified(true)
		}
		return err
	}
	a.mgr.SeedRelayKnown(pointID, resources)
	if p := cfg.Find(pointID); p != nil && p.Relay != nil && !p.Relay.HistoryInitialized {
		if err := a.store.SetRelayHistoryInitialized(pointID); err != nil {
			// The protective cache exists, so the marker can be retried later;
			// the snapshot must not be published as authorized until both steps
			// succeeded.
			return err
		}
		next := a.store.Config()
		a.setConfig(next)
	}
	return nil
}

// loadRelayKnown seeds every imported node's attribution before anything
// connects, and turns on the protection gate when a cache cannot be trusted.
func (a *app) loadRelayKnown() {
	if a.mgr == nil {
		return
	}
	unverified := false
	for _, p := range a.cfg.Points {
		if p.Protocol != model.ProtocolLANRelay {
			continue
		}
		initialized := p.Relay != nil && p.Relay.HistoryInitialized
		known, err := a.store.LoadRelayKnown(p.ID)
		switch {
		case err != nil:
			unverified = true
			if a.bus != nil {
				a.bus.Add("app", fmt.Sprintf("配置：局域网分享「%s」的历史归属无法读取：%v", p.Name, err))
			}
		case known == nil:
			if initialized {
				// A node that had a cache and lost it cannot prove which
				// targets are managed.
				unverified = true
				if a.bus != nil {
					a.bus.Add("app", fmt.Sprintf("配置：局域网分享「%s」的历史归属缺失，已暂缓未知目标直连", p.Name))
				}
			}
		default:
			a.mgr.SeedRelayKnown(p.ID, known.Resources)
		}
	}
	a.mgr.SetRelayHistoryUnverified(unverified)
}

// relayDiagnoseDraft is the connection check panel for an imported node.
type relayDiagnoseDraft struct {
	open    bool
	pointID string
	name    string
	running bool
	lines   []string
	err     string
	results chan relayDiagnoseResult
}

type relayDiagnoseResult struct {
	lines []string
	err   error
}

// relayCodeForPoint rebuilds the share code of an imported node from the stored
// metadata and the credential store. It never prints the token.
func (a *app) relayCodeForPoint(p *model.AccessPoint) (relay.ShareCode, error) {
	if p == nil || p.Relay == nil || p.Protocol != model.ProtocolLANRelay {
		return relay.ShareCode{}, fmt.Errorf("不是局域网中继接入点")
	}
	token, err := a.store.Password(p.ID)
	if err != nil || token == "" {
		return relay.ShareCode{}, fmt.Errorf("分享口令缺失，请重新导入")
	}
	return relay.ShareCode{
		Version:     p.Relay.Version,
		Host:        p.Server,
		Port:        p.Port,
		ShareID:     p.Relay.ShareID,
		Token:       token,
		Fingerprint: p.Relay.CertificateSHA256,
		Name:        p.Name,
	}, nil
}

// openRelayDiagnose starts the layered check for one imported node.
func (a *app) openRelayDiagnose(pointID string) {
	p := a.cfg.Find(pointID)
	if p == nil {
		return
	}
	d := &a.relayDiagnose
	d.open = true
	d.pointID = pointID
	d.name = p.Name
	d.lines = nil
	d.err = ""
	d.running = true
	if d.results == nil {
		d.results = make(chan relayDiagnoseResult, 2)
	}
	code, err := a.relayCodeForPoint(p)
	if err != nil {
		d.running = false
		d.err = err.Error()
		a.invalidate()
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		report := relay.Diagnose(ctx, code, relay.DiagnoseOptions{})
		res := relayDiagnoseResult{lines: relay.FormatReport(report)}
		d.results <- res
		a.invalidate()
	}()
	a.invalidate()
}

func (a *app) relayDiagnoseView(c *ui.Context) {
	d := &a.relayDiagnose
	if !d.open {
		return
	}
	select {
	case res := <-d.results:
		d.running = false
		d.lines = res.lines
		if res.err != nil {
			d.err = res.err.Error()
		}
	default:
	}
	t := c.Theme()
	ui.Modal(c, &d.open, func() {
		ui.Column(c).Width(dialogRegular).Gap(10).Children(func() {
			dialogHeader(c, "连接诊断", d.name)
			ui.Text(c, "诊断按口令 → TCP → 身份 → 认证 → 资源 → 业务依次检查；超时只说明未在期限内完成，不能据此断定是防火墙。").
				FontSize(11).TextColor(t.TextMuted).Wrap()
			ui.Scroll(c).MaxHeight(a.dialogBodyMaxHeight()).MinHeight(0).
				ScrollbarInsets(4, 2, 4, 0).Children(func() {
				ui.Column(c).Padding(0, 12, 6, 0).Gap(4).Children(func() {
					if d.running {
						ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
							ui.Spinner(c)
							ui.Text(c, "正在检查…").FontSize(12)
						})
					}
					for _, line := range d.lines {
						color := t.TextMuted
						if strings.HasPrefix(line, "✓") {
							color = t.Success
						} else if strings.HasPrefix(line, "✕") {
							color = t.Danger
						}
						ui.Text(c, line).FontSize(12).TextColor(color).Wrap()
					}
					if d.err != "" {
						ui.Text(c, d.err).FontSize(11).TextColor(t.Danger).Wrap()
					}
				})
			})
			dialogFooter(c, func() {
				if ui.Button(c, "关闭").FontSize(11).Clicked() {
					d.open = false
				}
				ui.Row(c).Grow(1)
				if ui.Button(c, "重新检查").FontSize(11).Disabled(d.running).Clicked() {
					a.openRelayDiagnose(d.pointID)
				}
			})
		})
	})
}

// openLANShareDiagnose reports what the local host can prove about its own
// share: the listener, the code, and the published scope. It does not pretend to
// test a colleague's network.
func (a *app) openLANShareDiagnose() {
	d := &a.relayDiagnose
	d.open = true
	d.pointID = ""
	d.name = "本机共享"
	d.running = false
	d.err = ""
	d.lines = nil
	view := relay.View{}
	if a.lanShare != nil {
		view = a.lanShare.View()
	}
	add := func(ok bool, text string) {
		mark := "✓"
		if !ok {
			mark = "✕"
		}
		d.lines = append(d.lines, mark+" "+text)
	}
	add(view.State == relay.StateRunning, "监听状态："+stateLabelOf(view.State))
	if view.State == relay.StateRunning {
		add(true, fmt.Sprintf("监听地址：%s:%d", view.Address, view.Port))
		add(true, fmt.Sprintf("活跃客户端：%d", view.Clients))
	}
	code, err := a.lanShareCode()
	if err == nil && code != "" {
		add(true, "分享口令可生成（已隐藏内容）")
	} else {
		add(false, "分享口令不可用："+errText(err))
	}
	add(true, "共享范围：整个接入点「"+orDash(view.PointName)+"」")
	if view.Failure != "" {
		d.lines = append(d.lines, "原因："+view.Failure)
	}
	a.invalidate()
}

func errText(err error) string {
	if err == nil {
		return "未知原因"
	}
	return err.Error()
}

// relayPointDraft is the read-only detail panel of an imported node. It exists
// so a relay node never ends up in the VPN login editor.
type relayPointDraft struct {
	open    bool
	pointID string
}

func (a *app) openRelayPoint(pointID string) {
	a.relayPoint = relayPointDraft{open: true, pointID: pointID}
	a.invalidate()
}

func (a *app) relayPointView(c *ui.Context) {
	d := &a.relayPoint
	if !d.open {
		return
	}
	p := a.cfg.Find(d.pointID)
	if p == nil {
		d.open = false
		return
	}
	t := c.Theme()
	view, _ := a.mgr.View(p.ID)
	ui.Modal(c, &d.open, func() {
		ui.Column(c).Width(dialogRegular).Gap(10).Children(func() {
			dialogHeader(c, "局域网中继接入点", p.Name)
			ui.Scroll(c).MaxHeight(a.dialogBodyMaxHeight()).MinHeight(0).
				ScrollbarInsets(4, 2, 4, 0).Children(func() {
				ui.Column(c).Padding(0, 14, 8, 0).Gap(8).Children(func() {
					ui.Text(c, "本机不直接登录这个网关：连接由同事的分享主机转发，公网走本机网络。").
						FontSize(12).TextColor(t.TextMuted).Wrap()
					rows := [][2]string{
						{"分享主机", net.JoinHostPort(p.Server, strconv.Itoa(p.Port))},
						{"状态", view.State.Label()},
						{"分享 ID", shortFingerprint(orDash(relayShareIDOf(p)))},
						{"证书指纹", shortFingerprint(orDash(relayPinOf(p)))},
						{"加入统一入口", boolLabel(p.InPool)},
						{"启动时自动连接", boolLabel(p.AutoConnect)},
					}
					for _, row := range rows {
						ui.Row(c).Gap(8).Children(func() {
							ui.Text(c, row[0]).FontSize(12).TextColor(t.TextMuted).Width(120)
							ui.Text(c, row[1]).FontSize(12).Wrap()
						})
					}
					if view.Error != "" {
						ui.Text(c, view.Error).FontSize(12).TextColor(t.Danger).Wrap()
					}
				})
			})
			dialogFooter(c, func() {
				if ui.Button(c, "删除接入点").FontSize(11).Background(t.Danger).
					TextColor(t.AccentText).Clicked() {
					d.open = false
					a.deleting = p.ID
				}
				ui.Row(c).Grow(1)
				if ui.Button(c, "连接诊断").FontSize(11).Clicked() {
					d.open = false
					a.openRelayDiagnose(p.ID)
				}
				if ui.Button(c, "关闭").FontSize(11).Clicked() {
					d.open = false
				}
			})
		})
	})
}

func relayShareIDOf(p *model.AccessPoint) string {
	if p.Relay == nil {
		return ""
	}
	return p.Relay.ShareID
}

func relayPinOf(p *model.AccessPoint) string {
	if p.Relay == nil {
		return ""
	}
	return p.Relay.CertificateSHA256
}

func boolLabel(v bool) string {
	if v {
		return "是"
	}
	return "否"
}
