package main

import (
	"fmt"
	"github.com/egoist/mygo/ui"
	"github.com/qy/easyconnect/internal/model"
	"github.com/qy/easyconnect/internal/routing"
	"strconv"
	"strings"
)

type routeDraft struct {
	open                                           bool
	tab                                            int
	target, network, binding, result               string
	query, filter                                  string
	pattern, protocol, ports, action, gateway, err string
	shared                                         map[string]*bool
	each, total                                    string
}

func (a *app) openRoutes() {
	a.routes = routeDraft{open: true, network: "tcp", binding: "自动归属", filter: "所有网关", protocol: "tcp", ports: "443", action: "自动", shared: map[string]*bool{}, each: strconv.Itoa(a.cfg.Settings.DialTimeoutMS), total: strconv.Itoa(a.cfg.Settings.TotalTimeoutMS)}
}

func (a *app) routeChoices(first string) []string {
	choices := []string{first}
	for _, p := range a.cfg.Points {
		choices = append(choices, a.pointChoice(p))
	}
	return choices
}

func (a *app) routePoint(choice string) string {
	for _, p := range a.cfg.Points {
		if a.pointChoice(p) == choice {
			return p.ID
		}
	}
	return ""
}

func formatRouteDecision(d routing.Decision) string {
	action := map[string]string{"vpn": "VPN", "direct": "原网络", "blocked": "阻止"}[d.Action]
	lines := []string{action + " · " + d.Reason}
	if d.RuleID != "" {
		lines = append(lines, "用户规则："+d.RuleID)
	}
	for _, m := range d.Matches {
		state := "仅归属记录"
		if m.Current {
			state = "当前声明"
		}
		if m.Authorized {
			state = "当前授权匹配"
		}
		lines = append(lines, fmt.Sprintf("%s · %s · %s", m.GatewayID, m.Source, state))
	}
	for _, c := range d.Candidates {
		line := fmt.Sprintf("候选：%s · 会话 %d · 资源 %s", c.Name, c.Generation, c.Version)
		if c.NeedsResolution {
			line += " · 需网关解析并再次校验地址授权"
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func (a *app) previewRoute() {
	d := &a.routes
	d.result = formatRouteDecision(a.mgr.PreviewRoute(routing.Request{Network: d.network, Address: strings.TrimSpace(d.target), GatewayID: a.routePoint(d.binding)}))
}

func parseRoutePorts(value string) (int, int, error) {
	parts := strings.Split(value, "-")
	lo, err := parsePort(strings.TrimSpace(parts[0]), "端口")
	if err != nil {
		return 0, 0, err
	}
	hi := lo
	if len(parts) > 2 {
		return 0, 0, fmt.Errorf("端口格式为 443 或 1-65535")
	}
	if len(parts) == 2 {
		hi, err = parsePort(strings.TrimSpace(parts[1]), "结束端口")
	}
	if err != nil || hi < lo {
		return 0, 0, fmt.Errorf("端口范围无效")
	}
	return lo, hi, nil
}

func (a *app) updateRoutes(change func(*model.Settings) error) {
	_, err := a.store.Update(func(cfg *model.Config) error {
		if err := change(&cfg.Settings); err != nil {
			return err
		}
		if err := cfg.Settings.Validate(); err != nil {
			return err
		}
		for _, r := range cfg.Settings.RoutePolicies {
			if r.GatewayID != "" && cfg.Find(r.GatewayID) == nil {
				return fmt.Errorf("指定网关不存在")
			}
		}
		for _, b := range cfg.Settings.DNSBindings {
			if cfg.Find(b.GatewayID) == nil {
				return fmt.Errorf("DNS 默认网关不存在")
			}
		}
		for _, g := range cfg.Settings.SharedExits {
			for _, id := range g.Gateways {
				if cfg.Find(id) == nil {
					return fmt.Errorf("共享出口网关不存在")
				}
			}
		}
		return nil
	})
	if err == nil {
		err = a.saveConfig()
	}
	if err != nil {
		a.routes.err = err.Error()
		return
	}
	a.routes.err = ""
	a.routes.result = ""
	a.toast = "路由设置已保存"
}

func (a *app) addRoutePolicy(shared bool) {
	d := &a.routes
	lo, hi, err := parseRoutePorts(d.ports)
	if err != nil {
		d.err = err.Error()
		return
	}
	a.updateRoutes(func(s *model.Settings) error {
		if shared {
			var ids []string
			for _, p := range a.cfg.Points {
				if selected := d.shared[p.ID]; selected != nil && *selected {
					ids = append(ids, p.ID)
				}
			}
			s.SharedExits = append(s.SharedExits, routing.Group{ID: model.NewID(), Pattern: strings.TrimSpace(d.pattern), Protocol: d.protocol, PortMin: lo, PortMax: hi, Gateways: ids})
		} else {
			action := map[string]string{"自动": "auto", "指定网关": "gateway", "原网络": "direct", "阻止": "block"}[d.action]
			id := ""
			if action == "gateway" {
				id = a.routePoint(d.gateway)
			}
			s.RoutePolicies = append(s.RoutePolicies, routing.Policy{ID: model.NewID(), Pattern: strings.TrimSpace(d.pattern), Protocol: d.protocol, PortMin: lo, PortMax: hi, Action: action, GatewayID: id})
		}
		return nil
	})
}

func (a *app) routesView(c *ui.Context) {
	d := &a.routes
	if !d.open {
		return
	}
	ui.Modal(c, &d.open, func() {
		ui.Column(c).Width(dialogWide).Gap(10).Children(func() {
			dialogHeader(c, "网络授权与路由", "只读预览：不查询 DNS、不连业务端口、不分配映射地址")
			// 弹窗内的分段也用与主界面一致的胶囊导航。
			ui.Segmented(c, &d.tab, "路由预览", "授权资源", "用户策略").Label("授权视图")
			ui.Scroll(c).MaxHeight(a.dialogBodyHeight(260)).MinHeight(0).
				ScrollbarInsets(6, 6, 6, 6).Children(func() {
				ui.Column(c).Gap(10).Children(func() {
					switch d.tab {
					case 0:
						ui.Text(c, "预览只读取当前规则，不查询 DNS、不连接业务端口，也不分配映射地址。").FontSize(13).Wrap()
						ui.Field(c, "目标（主机:端口）", func() { ui.TextInput(c, &d.target).Placeholder("db.corp.example:443") })
						ui.Field(c, "协议", func() { ui.Select(c, &d.network, []string{"tcp", "udp", "tcp6", "udp6"}) })
						ui.Field(c, "入口绑定", func() { ui.Select(c, &d.binding, a.routeChoices("自动归属")) })
						if ui.PrimaryButton(c, "预览路由").Clicked() {
							a.previewRoute()
						}
						ui.Text(c, d.result).FontSize(13).Wrap()
					case 1:
						a.routeResources(c)
					case 2:
						a.routePolicies(c)
					}
				})
			})
			if d.err != "" {
				ui.Text(c, d.err).FontSize(11).TextColor(c.Theme().Danger).Wrap()
			}
			dialogFooter(c, func() {
				ui.Row(c).Grow(1)
				if ui.Button(c, "关闭").FontSize(11).Clicked() {
					d.open = false
				}
			})
		})
	})
}

func (a *app) routeResources(c *ui.Context) {
	d := &a.routes
	ui.Text(c, "网关授权只读；DNS 声明用于归属解析，不授予业务端口权限。离线记录仅用于防止错误回退。").FontSize(13).Wrap()
	ui.Select(c, &d.filter, a.routeChoices("所有网关"))
	ui.SearchField(c, &d.query).Placeholder("搜索域名、地址或网关")
	query := strings.ToLower(strings.TrimSpace(d.query))
	count := 0
	for _, g := range a.mgr.ResourceGateways() {
		if id := a.routePoint(d.filter); id != "" && id != g.ID {
			continue
		}
		state := "离线归属记录"
		s := g.Known
		if g.Online {
			state = "在线授权"
			s = g.Current
		}
		if s == nil {
			continue
		}
		var lines []string
		for _, r := range s.IPRules {
			lines = append(lines, fmt.Sprintf("IP %s–%s · %s · %d–%d", r.Min, r.Max, r.Protocol, r.PortMin, r.PortMax))
		}
		for _, r := range s.DomainRules {
			lines = append(lines, fmt.Sprintf("域名 %s · %s · %d–%d", r.Domain, r.Protocol, r.PortMin, r.PortMax))
		}
		for _, r := range s.StaticDNS {
			lines = append(lines, "静态 DNS "+r.Name+" → "+strings.Join(r.Addresses, ", "))
		}
		for _, r := range s.InternalDomains {
			lines = append(lines, "DNS 后缀 "+r)
		}
		for _, line := range lines {
			if query != "" && !strings.Contains(strings.ToLower(line+g.Name), query) {
				continue
			}
			if count >= 150 {
				ui.Text(c, "仅显示前 150 条，请缩小搜索范围。").FontSize(11)
				return
			}
			count++
			ui.Column(c).Padding(6).Gap(3).Children(func() {
				ui.Text(c, line).FontSize(13).Wrap()
				ui.Text(c, fmt.Sprintf("来源 %s · %s · 会话 %d · 资源 %s", g.Name, state, g.Generation, g.Version)).FontSize(11).TextColor(c.Theme().TextMuted).Wrap()
			})
		}
	}
	if count == 0 {
		ui.Text(c, "没有匹配的网络授权记录").FontSize(13)
	}
	ui.Text(c, "使用路由预览检查具体端口的归属冲突；最近实际出口可在访问日志的详情中查看。").FontSize(11).Wrap()
}

func (a *app) routePolicies(c *ui.Context) {
	d := &a.routes
	ui.Text(c, "用户策略按列表顺序首次匹配生效。指定网关仍须通过授权；同业务出口只有明确添加后才能相互重试。").FontSize(13).Wrap()
	ui.Field(c, "域名 / IP / CIDR", func() { ui.TextInput(c, &d.pattern).Placeholder("git.corp.example 或 10.20.0.0/24") })
	ui.Field(c, "协议", func() { ui.Select(c, &d.protocol, []string{"tcp", "udp", "all"}) })
	ui.Field(c, "端口范围", func() { ui.TextInput(c, &d.ports).Placeholder("443 或 1-65535") })
	ui.Field(c, "动作", func() { ui.Select(c, &d.action, []string{"自动", "指定网关", "原网络", "阻止"}) })
	if d.action == "指定网关" {
		ui.Select(c, &d.gateway, a.routeChoices("请选择网关"))
	}
	if ui.Button(c, "添加策略").Clicked() {
		a.addRoutePolicy(false)
	}
	for i, p := range a.cfg.Settings.RoutePolicies {
		ui.Row(c).Gap(6).Children(func() {
			ui.Text(c, fmt.Sprintf("%d. %s · %s:%d–%d · %s %s", i+1, p.Pattern, p.Protocol, p.PortMin, p.PortMax, map[string]string{"auto": "自动", "gateway": "指定网关", "direct": "原网络", "block": "阻止"}[p.Action], p.GatewayID)).FontSize(11).Grow(1).Wrap()
			if ui.Button(c, "上移").Label("上移策略 " + p.ID).Disabled(i == 0).Clicked() {
				a.updateRoutes(func(s *model.Settings) error {
					s.RoutePolicies[i-1], s.RoutePolicies[i] = s.RoutePolicies[i], s.RoutePolicies[i-1]
					return nil
				})
			}
			if ui.Button(c, "删除").Label("删除策略 " + p.ID).Clicked() {
				a.updateRoutes(func(s *model.Settings) error {
					s.RoutePolicies = append(s.RoutePolicies[:i], s.RoutePolicies[i+1:]...)
					return nil
				})
			}
		})
	}
	ui.Divider(c)
	ui.Text(c, "同业务备用出口（沿用上方目标、协议和端口）").FontSize(13).Bold()
	for _, p := range a.cfg.Points {
		if d.shared[p.ID] == nil {
			v := false
			d.shared[p.ID] = &v
		}
		ui.Checkbox(c, d.shared[p.ID], a.pointChoice(p))
	}
	if ui.Button(c, "添加同业务出口组").Clicked() {
		a.addRoutePolicy(true)
	}
	for i, g := range a.cfg.Settings.SharedExits {
		ui.Row(c).Gap(6).Children(func() {
			ui.Text(c, fmt.Sprintf("%s · %s:%d–%d · %s", g.Pattern, g.Protocol, g.PortMin, g.PortMax, strings.Join(g.Gateways, ", "))).FontSize(11).Grow(1).Wrap()
			if ui.Button(c, "删除").Label("删除出口组 " + g.ID).Clicked() {
				a.updateRoutes(func(s *model.Settings) error {
					s.SharedExits = append(s.SharedExits[:i], s.SharedExits[i+1:]...)
					return nil
				})
			}
		})
	}
	ui.Field(c, "单次拨号预算（毫秒）", func() { ui.TextInput(c, &d.each) })
	ui.Text(c, "域名默认 DNS 归属（沿用上方域名；与业务端口策略分开）").FontSize(13).Bold()
	ui.Select(c, &d.gateway, a.routeChoices("请选择网关"))
	if ui.Button(c, "添加 DNS 默认归属").Clicked() {
		a.updateRoutes(func(s *model.Settings) error {
			s.DNSBindings = append(s.DNSBindings, routing.DNSBinding{ID: model.NewID(), Pattern: strings.TrimSpace(d.pattern), GatewayID: a.routePoint(d.gateway)})
			return nil
		})
	}
	for i, b := range a.cfg.Settings.DNSBindings {
		ui.Row(c).Gap(6).Children(func() {
			ui.Text(c, b.Pattern+" → "+b.GatewayID).FontSize(11).Grow(1)
			if ui.Button(c, "删除").Label("删除 DNS 归属 " + b.ID).Clicked() {
				a.updateRoutes(func(s *model.Settings) error {
					s.DNSBindings = append(s.DNSBindings[:i], s.DNSBindings[i+1:]...)
					return nil
				})
			}
		})
	}
	ui.Field(c, "总拨号预算（毫秒）", func() { ui.TextInput(c, &d.total) })
	if ui.Button(c, "保存拨号预算").Clicked() {
		a.updateRoutes(func(s *model.Settings) error {
			each, e1 := strconv.Atoi(d.each)
			total, e2 := strconv.Atoi(d.total)
			if e1 != nil || e2 != nil || each < 1 || total < 1 {
				return fmt.Errorf("预算必须为正整数")
			}
			s.DialTimeoutMS, s.TotalTimeoutMS = each, total
			return nil
		})
	}
}
