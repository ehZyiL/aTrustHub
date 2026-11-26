package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/ehzyil/connect-hub/internal/components"
	"github.com/ehzyil/connect-hub/internal/model"
	relay "github.com/ehzyil/connect-hub/internal/relay/contract"
	relayfirewall "github.com/ehzyil/connect-hub/internal/relay/firewall"
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
	// saveFailed marks a switch-off whose preference could not be written; the
	// panel then offers a retry instead of silently claiming success.
	saveFailed bool
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
	// discovery is the 允许同事发现 checkbox of the enable form. It is an
	// explicit choice saved with the rest of the intent, default-checked only
	// when the user has never chosen before.
	discovery        bool
	discoveryName    string
	discoveryTouched bool
	// discoveryEditing opens the inline rename field of the running panel.
	discoveryEditing bool
	discoveryBusy    bool
	// discoverySavePending means the user turned discovery off but the
	// preference could not be written; the network is already stopped and the
	// panel offers a retry.
	discoverySavePending bool
	results              chan lanShareResult
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
	if virtualInterface(name) {
		return 1
	}
	return 0
}

// virtualInterface reports whether an adapter is a container bridge, a VM switch
// or a VPN tunnel rather than the LAN a colleague sits on.
//
// The names differ per platform and Windows uses localized friendly names
// ("以太网", "WLAN"), so this list can only be a hint: it orders the picker and
// labels the entries. Whether an address can actually host a share is decided by
// name-independent facts (a LAN-sized subnet), never by this function alone.
func virtualInterface(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	for _, prefix := range []string{
		// Containers, VM switches, host bridges (Linux / Windows / macOS).
		"docker", "veth", "br-", "virbr", "vnet", "vethernet", "vmnet", "vboxnet",
		"lxc", "cni", "podman", "incus", "mpqemu", "bridge", "tap",
		// Windows: Hyper-V/WSL switches and VPN clients.
		"loopback", "npcap", "hyper-v", "local area connection*",
		// This program's own adapters: the Windows capture device (ECH-<id>, which
		// is normally on 198.19.0.0/16 and so already fails the RFC1918 test) and
		// the upstream Wintun names (aTrustHubN, ZJU Connect). Naming them here
		// means the classification does not rest on the address pool alone.
		"ech-", "atrusthub", "zju connect",
		// Tunnels and VPNs (Linux tun0/wg0/tailscale0, macOS utunN,
		// Windows Wintun/WireGuard/OpenVPN adapters).
		"tun", "utun", "wg", "wintun", "wireguard", "openvpn", "tailscale", "zerotier",
		"nordlynx", "proton", "surfshark", "mullvad", "nebula", "hamachi", "n2n", "zt",
		"isatap", "teredo", "6to4",
		// macOS point-to-point / Apple wireless direct.
		"awdl", "llw", "gif", "stf", "ipsec", "pdp_ip",
	} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

// lanShareChanged is the controller's change notification. Discovery follows the
// share from here, not from the render loop.
func (a *app) lanShareChanged() {
	a.kickLANDiscovery()
	a.invalidateCoalesced()
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
	// Verify any rule left from the previous run before this run relies on it:
	// an unverified rule is either reused (same share, same scope) or removed.
	a.syncLanShareFirewall()
	a.resumeLANDiscovery()
}

// shutdownLANShare stops serving but keeps the enable intent, so the next start
// resumes it.
func (a *app) shutdownLANShare() {
	// The announcement goes before the listener: colleagues must not be able to
	// dial a share that is already going away.
	a.shutdownLANDiscovery()
	if a.lanShare != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = a.lanShare.Shutdown(ctx)
		cancel()
	}
	// The listener is closed, so the rule no longer serves anything. A failure
	// keeps the journal entry for the next start; it must not block quitting —
	// but it does get a bounded chance to finish before the process exits.
	a.cancelPendingFirewallOps()
	a.reconcileLanShareFirewall(a.lanShareViewState())
	if !a.awaitFirewallIdle(relayfirewall.FirewallShutdownBudget) {
		a.tunLogf("局域网分享：防火墙规则清理未在退出前完成，已保留待处理记录")
	}
}

// lanShareEnabled reports whether the share intent is on.
func (a *app) lanShareEnabled() bool {
	return a.lanShare != nil && a.lanShare.View().Enabled
}

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
	if view.FailureCode == "unavailable" {
		return "分享组件不可用：" + view.Failure
	}
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
	// A share that was never asked about discovery shows the box checked in the
	// enable form (an explicit choice is required to save), while a share that
	// already chose false keeps it unchecked.
	d.discovery = true
	d.discoveryTouched = false
	if settings.DiscoveryEnabled != nil {
		d.discovery = *settings.DiscoveryEnabled
		d.discoveryTouched = true
	}
	d.discoveryName = settings.DiscoveryName
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

// openLANShareFor opens the panel with one access point preselected, which is
// what the per-point detail action does.
func (a *app) openLANShareFor(pointID string) {
	a.openLANShare()
	d := &a.lanShareUI
	if pointID != "" {
		d.pointID = pointID
		// The panel re-reads the usable addresses for this run; a stale
		// interface choice from another network is not reused silently.
		d.interfaceName, d.ipv4 = "", ""
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

// lanCandidate is one selectable address plus what the panel needs to explain it.
type lanCandidate struct {
	iface   relay.Interface
	subnet  string
	lanSize bool // the subnet has room for other hosts
	virtual bool
}

// newLANCandidates annotates the enumerated addresses. subnetOf is injected so
// the classification can be tested without depending on the host's interfaces.
func newLANCandidates(list []relay.Interface, subnetOf func(string) (string, error)) []lanCandidate {
	out := make([]lanCandidate, 0, len(list))
	for _, cand := range list {
		subnet := ""
		if subnetOf != nil {
			if got, err := subnetOf(cand.IPv4); err == nil {
				subnet = got
			}
		}
		out = append(out, lanCandidate{
			iface:   cand,
			subnet:  subnet,
			lanSize: lanSizedCIDR(subnet),
			virtual: virtualInterface(cand.Name),
		})
	}
	return out
}

// lanSizedCIDR reports whether a subnet can hold another host. A /31 or /32 is a
// point-to-point link (a tunnel), not a LAN, whatever the adapter is called.
func lanSizedCIDR(cidr string) bool {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	ones, bits := network.Mask.Size()
	return bits != 0 && ones <= bits-2
}

// recommendLAN returns the index to preselect, or -1 when no candidate is a real
// LAN. It prefers the default route's address, but only when that address is a
// LAN-sized non-virtual adapter: a VPN tunnel or a container bridge is very often
// the default route, and recommending it would send the share to a network no
// colleague can reach.
func recommendLAN(cands []lanCandidate, outbound string) int {
	for i, c := range cands {
		if c.iface.IPv4 == outbound && !c.virtual && c.lanSize {
			return i
		}
	}
	for i, c := range cands {
		if !c.virtual && c.lanSize {
			return i
		}
	}
	return -1
}

// lanChoiceLabel is what the picker shows for one candidate.
func lanChoiceLabel(cand lanCandidate, recommended bool) string {
	label := cand.iface.Name + " · " + cand.iface.IPv4
	if cand.subnet != "" {
		label += " · " + cand.subnet
	}
	switch {
	case recommended:
		label += "（推荐）"
	case cand.virtual:
		label += "（虚拟网卡，其他设备通常不可达）"
	case cand.subnet != "" && !cand.lanSize:
		// Unknown subnet must not be described as point-to-point; only a
		// measured /31 or /32 is.
		label += "（点对点地址，其他设备不可达）"
	}
	return label
}

// relayInterfaceChoices returns the label -> address mapping the panel offers.
//
// A colleague can only reach an address inside their own subnet, so each choice
// shows the subnet and the most likely one is marked: the default route when it
// is a real LAN, otherwise the first LAN-sized physical adapter.
func (a *app) relayInterfaceChoices() ([]string, map[string]relay.Interface) {
	cands := newLANCandidates(lanAddresses{}.LANCandidates(), relayfirewall.SubnetOfAddress)
	pick := recommendLAN(cands, outboundIPv4())
	labels := make([]string, 0, len(cands))
	byLabel := make(map[string]relay.Interface, len(cands))
	for i, cand := range cands {
		label := lanChoiceLabel(cand, i == pick)
		labels = append(labels, label)
		byLabel[label] = cand.iface
	}
	return labels, byLabel
}

// outboundIPv4 reports the local address of the default route. A connected UDP
// socket performs the route lookup without sending a packet, so this costs
// nothing and works on every platform.
func outboundIPv4() string {
	conn, err := net.Dial("udp4", "192.0.2.1:9") // TEST-NET-1, never contacted
	if err != nil {
		return ""
	}
	defer conn.Close()
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || addr.IP == nil {
		return ""
	}
	return addr.IP.To4().String()
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
			if a.lanShare == nil || a.lanShare.Component().Availability != components.Ready {
				ui.Text(c, "分享组件不可用，请检查安装包；基础 VPN 连接仍可使用。").Wrap()
				if ui.Button(c, "关闭面板").Clicked() {
					d.open = false
				}
				return
			}
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
				if view.FailureCode == "persist" && !view.Enabled {
					if ui.Button(c, "重试保存关闭状态").FontSize(11).Disabled(d.busy).Clicked() {
						a.retryPersistLANShareDisable()
					}
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
			// No remembered choice: start on the recommendation, if there is one.
			cands := newLANCandidates(lanAddresses{}.LANCandidates(), relayfirewall.SubnetOfAddress)
			if pick := recommendLAN(cands, outboundIPv4()); pick >= 0 {
				for label, cand := range iaByLabel {
					if cand.IPv4 == cands[pick].iface.IPv4 {
						current = label
					}
				}
			}
			if current == "" {
				current = iaLabels[0]
			}
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
	ui.Column(c).Gap(4).Children(func() {
		ui.Checkbox(c, &d.discovery, "允许同一网络的同事发现")
		ui.Text(c, "同一网络的其他设备可以看到公开名称和连接地址；加入仍需分享口令。").
			FontSize(11).TextColor(c.Theme().TextMuted).Wrap()
		if d.discovery {
			ui.Field(c, "公开名称", func() {
				ui.TextInput(c, &d.discoveryName).
					Placeholder(a.discoveryNamePlaceholder()).
					Width(320).Changed()
				ui.Text(c, "留空使用默认名称；不会使用 VPN 名称、账号或计算机名。").
					FontSize(11).TextColor(c.Theme().TextMuted).Wrap()
			})
		}
	})
	ui.Checkbox(c, &d.advanced, "高级选项（固定端口）")
	if d.advanced {
		ui.Field(c, "监听端口", func() {
			ui.TextInput(c, &d.portText).Placeholder("留空自动分配").Width(140)
		})
	}
}

func (a *app) lanShareManageBody(c *ui.Context, d *lanShareDraft, view relay.View) {
	t := c.Theme()
	subnet := ""
	if view.Address != "" {
		if got, err := relayfirewall.SubnetOfAddress(view.Address); err == nil {
			subnet = got
		}
	}
	rows := [][2]string{
		{"共享接入点", orDash(view.PointName)},
		{"监听地址", orDash(view.Address)},
		{"所在网段", orDash(subnet)},
		{"端口", fmt.Sprint(orZero(view.Port))},
		{"运行状态", stateLabelOf(view.State)},
		{"重启后恢复", "是（点击关闭共享后不再恢复）"},
	}
	if !view.CertExpiry.IsZero() {
		rows = append(rows, [2]string{"证书有效期至", view.CertExpiry.Format("2006-01-02")})
	}
	if subnet != "" {
		ui.Text(c, "同事需要和本机在同一网段（"+subnet+"）内，并且没有被 Wi-Fi 访客网络或 AP 隔离挡住。").
			FontSize(11).TextColor(t.TextMuted).Wrap()
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
	a.lanShareDiscoveryView(c, view)
	if view.State == relay.StateRunning {
		info := relayfirewall.FirewallInfo()
		ui.Column(c).Gap(3).Children(func() {
			for _, line := range info.Lines {
				ui.Text(c, line).FontSize(11).TextColor(t.TextMuted).Wrap()
			}
			if info.Automatic {
				ui.Text(c, "本程序只在点击「允许局域网连接」并完成系统授权后修改防火墙，不会在开启共享时静默改规则。").
					FontSize(11).TextColor(t.TextMuted).Wrap()
			}
		})
		a.lanShareFirewallView(c, view)
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
			if res.action == "discovery" || res.action == "discovery-name" ||
				res.action == "discovery-retry" {
				d.discoveryBusy = false
				if res.err == nil {
					d.discoveryEditing = false
					d.discoverySavePending = false
				}
				if res.saveFailed {
					d.discoverySavePending = true
				}
			}
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
	if name := strings.TrimSpace(d.discoveryName); d.discovery && name != "" {
		if err := model.ValidDiscoveryName(name); err != nil {
			d.err = err.Error()
			return
		}
	}
	opts := relay.EnableOptions{
		PointID:       d.pointID,
		InterfaceName: d.interfaceName,
		PreferredIPv4: d.ipv4,
		Port:          port,
		Discovery:     d.discovery,
		DiscoveryName: d.discoveryName,
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
			// The rule only exists for the share port; it goes with the share. A
			// creation still waiting on the elevation prompt is revoked too.
			a.cancelPendingFirewallOps()
			a.syncLanShareFirewall()
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

// retryPersistLANShareDisable re-attempts saving Enabled=false after a failed
// disable, and only then removes the recovery identity.
func (a *app) retryPersistLANShareDisable() {
	d := &a.lanShareUI
	if a.lanShare == nil {
		return
	}
	d.busy, d.busyAction = true, "retry-persist"
	d.err, d.notice = "", ""
	go func() {
		err := a.lanShare.RetryPersistDisable()
		notice := ""
		if err == nil {
			notice = "关闭状态已保存，下次启动不会恢复。"
		}
		a.postLANShareResult(lanShareResult{action: "retry-persist", err: err, notice: notice})
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
func (a *app) saveRelaySnapshot(pointID string, ident vpn.RelaySnapshotSource, resources *workeripc.ResourceSnapshot) error {
	if resources == nil {
		return nil
	}
	source := store.RelaySource{
		ShareID:     ident.ShareID,
		Fingerprint: ident.Fingerprint,
		Label:       ident.Fingerprint + "/" + ident.ShareID,
	}
	write, err := a.store.SaveRelayKnown(pointID, source, resources)
	if err != nil {
		if errors.Is(err, store.ErrRelayKnownStaleSource) {
			// The node was deleted or re-imported while this session was running.
			// Its snapshot can never be trusted for the current configuration, and
			// turning on protection would refuse ordinary public traffic for a node
			// the user can no longer see. Drop the callback instead.
			if a.bus != nil {
				a.bus.Add("app", "配置：已忽略已删除或已更换身份的分享的历史归属回调")
			}
			return err
		}
		// The protection gap must stay visible: the gate refuses unknown targets
		// instead of pretending the history is intact.
		if a.mgr != nil {
			a.mgr.BlockRelayAutoConnect(pointID, true)
		}
		return err
	}
	if write.Incomplete {
		// The cache this snapshot merged into was corrupt or missing, so targets
		// owned by the lost history are unknowable. Protect what is known and
		// keep the node blocked until the user decides otherwise.
		a.mgr.SeedRelayKnownIncomplete(pointID, resources)
	} else {
		a.mgr.SeedRelayKnown(pointID, resources)
	}
	// The marker check reads the store, not a.cfg: this goroutine must not touch
	// the UI-thread copy of the configuration.
	initialized := false
	persisted := a.store.Config()
	if p := persisted.Find(pointID); p != nil && p.Relay != nil {
		initialized = p.Relay.HistoryInitialized
	}
	if !initialized {
		if err := a.store.SetRelayHistoryInitialized(pointID); err != nil {
			// The protective cache exists, so the marker can be retried later;
			// the snapshot must not be published as authorized until both steps
			// succeeded.
			return err
		}
		// The marker is visible in the panel, so the UI copy of the config has
		// to catch up. It is re-read on the UI thread; this goroutine never
		// writes a.cfg (see requestConfigReload).
		a.requestConfigReload()
	}
	return nil
}

// loadRelayKnown seeds every imported node's attribution before anything
// connects, and turns on the protection gate when a cache cannot be trusted.
func (a *app) loadRelayKnown() {
	if a.mgr == nil {
		return
	}
	for _, p := range a.cfg.Points {
		if p.Protocol != model.ProtocolLANRelay {
			continue
		}
		initialized := p.Relay != nil && p.Relay.HistoryInitialized
		known, err := a.store.LoadRelayKnown(p.ID)
		switch {
		case err != nil:
			a.mgr.BlockRelayAutoConnect(p.ID, true)
			if a.bus != nil {
				a.bus.Add("app", fmt.Sprintf("配置：局域网分享「%s」的历史归属无法读取，已暂停自动连接（可手动登录修复）：%v", p.Name, err))
			}
		case known == nil:
			if initialized {
				// A node that had a cache and lost it cannot prove which
				// targets are managed.
				a.mgr.BlockRelayAutoConnect(p.ID, true)
				if a.bus != nil {
					a.bus.Add("app", fmt.Sprintf("配置：局域网分享「%s」的历史归属缺失，已暂停自动连接并暂缓未知目标直连", p.Name))
				}
			}
		case known.Incomplete:
			// The file exists but is known to be missing entries: the node stays
			// out of automatic login and the gate stays on.
			a.mgr.SeedRelayKnownIncomplete(p.ID, known.Resources)
			if a.bus != nil {
				a.bus.Add("app", fmt.Sprintf("配置：局域网分享「%s」的历史归属不完整，已暂停自动连接；旧目标仍不会直连", p.Name))
			}
		default:
			a.mgr.SeedRelayKnown(p.ID, known.Resources)
		}
	}
}

// clearRelayHistoryProtection is the explicit user decision to accept that the
// lost history cannot be recovered: their old owned targets will no longer be
// recognised as managed. Nothing calls this automatically.
// relayHistoryConfirmView asks before dropping the protection for a node: the
// consequence is that targets from the lost history stop being recognised.
func (a *app) relayHistoryConfirmView(c *ui.Context) {
	if a.askingClearRelayHistory == "" {
		return
	}
	id := a.askingClearRelayHistory
	p := a.cfg.Find(id)
	if p == nil {
		a.askingClearRelayHistory = ""
		return
	}
	t := c.Theme()
	open := true
	ui.Modal(c, &open, func() {
		ui.Column(c).Width(dialogRegular).Gap(10).Children(func() {
			dialogHeader(c, "解除历史保护", p.Name)
			ui.Text(c, "该分享的历史归属缓存已损坏或缺失，无法证明哪些地址以前属于这个接入点。").
				FontSize(12).Wrap()
			ui.Text(c, "解除后，这些地址将不再被视为受管目标，可能按普通公网从本机直连。").
				FontSize(12).TextColor(t.Warning).Wrap()
			dialogFooter(c, func() {
				if ui.Button(c, "保持保护").FontSize(11).Clicked() {
					a.askingClearRelayHistory = ""
					a.invalidate()
				}
				ui.Row(c).Grow(1)
				if ui.PrimaryButton(c, "确认解除").FontSize(11).Clicked() {
					a.askingClearRelayHistory = ""
					if err := a.clearRelayHistoryProtection(id); err != nil {
						a.toast = "解除失败：" + err.Error()
					}
					a.invalidate()
				}
			})
		})
	})
	if !open {
		a.askingClearRelayHistory = ""
		a.invalidate()
	}
}

func (a *app) clearRelayHistoryProtection(pointID string) error {
	if a.store != nil {
		if err := a.store.ClearRelayKnownIncomplete(pointID); err != nil {
			return err
		}
	}
	if a.mgr != nil {
		a.mgr.BlockRelayAutoConnect(pointID, false)
	}
	a.toast = "已解除该分享的历史保护：之前归属不明目标今后按普通规则处理"
	a.invalidate()
	return nil
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

func (a *app) checkRelay(ctx context.Context, code relay.ShareCode) ([]string, error) {
	if a.relayCheck == nil {
		return nil, errors.New("分享诊断组件不可用")
	}
	return a.relayCheck(ctx, code)
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
		lines, err := a.checkRelay(ctx, code)
		res := relayDiagnoseResult{lines: lines, err: err}
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
					// A node whose history is unknown or incomplete stays out of
					// automatic login and keeps unknown targets off the direct
					// path. Only the user can accept that loss.
					if blocked := a.mgr.RelayAutoConnectBlocked(p.ID); blocked {
						ui.Text(c, "历史归属不完整或无法读取：本节点不自动连接，未知目标不会直连。恢复可信历史前保持此状态。").
							FontSize(11).TextColor(t.Warning).Wrap()
						if ui.Button(c, "解除历史保护…").FontSize(11).Clicked() {
							d.open = false
							a.askingClearRelayHistory = p.ID
							a.invalidate()
						}
					}
					// System proxy is a separate, explicit step: connecting a
					// share never changes it on its own.
					if view.State == vpn.StateOnline {
						if reason := a.captureBlocker(captureSystem); reason != "" {
							ui.Text(c, "系统代理当前不可开启："+reason).FontSize(11).TextColor(t.TextMuted).Wrap()
						} else if a.captureMode() == captureSystem {
							ui.Text(c, "系统代理已开启：支持系统代理的应用会走本机入口，再按资源归属分流。").
								FontSize(11).TextColor(t.TextMuted).Wrap()
						} else if ui.PrimaryButton(c, "开启系统代理").FontSize(11).Clicked() {
							d.open = false
							a.applyCaptureMode(captureSystem)
							a.invalidate()
						}
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
