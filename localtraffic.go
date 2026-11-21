package main

import (
	"fmt"
	"net"
	"strings"
	"unicode"

	"github.com/ehzyil/connect-hub/internal/localapps"
	"github.com/ehzyil/connect-hub/internal/vpn"
)

func trafficBytes(n uint64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	v, i := float64(n), 0
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d B", n)
	}
	return fmt.Sprintf("%.1f %s", v, units[i])
}

// Events carry a launch-time name snapshot. Background callbacks never access
// mutable GUI configuration and never format arbitrary core error strings.
func (a *app) logLocalAccess(e localapps.AccessEvent) {
	if a.bus == nil {
		return
	}
	source, line := localAccessLine(e)
	a.bus.Upsert(source, line)
}

func (a *app) logLocalAppError(name string, err error) {
	if a.bus != nil && err != nil {
		a.bus.Add("app", fmt.Sprintf("本机软件「%s」接管失败：%s", logField(name), logField(err.Error())))
	}
}

func localAccessLine(e localapps.AccessEvent) (string, string) {
	r := e.Result
	target := r.Target
	if target == "" {
		target = e.Target
	}
	if host, port, err := net.SplitHostPort(target); err != nil || host == "" || strings.ContainsAny(host, "/?#@\\") || port == "" {
		target = "无效目标地址"
	}
	path := "路径未报告"
	switch r.Route {
	case "vpn":
		path = "VPN"
	case "direct":
		path = "原出口"
	case "blocked":
		path = "已阻止"
	}
	rule := ""
	switch r.Rule {
	case "domain_resource":
		rule = fmt.Sprintf("域名授权 %s %s/%d–%d", logField(r.Domain), logField(r.Protocol), r.PortMin, r.PortMax)
	case "ip_resource":
		rule = fmt.Sprintf("IP 授权 %s–%s %s/%d–%d", logField(r.IPMin), logField(r.IPMax), logField(r.Protocol), r.PortMin, r.PortMax)
	case "default":
		rule = "未命中 VPN 资源"
	case "acl":
		rule = "目标或端口未获 VPN 授权"
	case "alias":
		rule = "域名映射失效"
	case "dns":
		rule = "域名解析失败"
	case "forced":
		rule = "核心指定 VPN"
	}
	source, state := vpn.AccessOK, "TCP 已建立"
	if r.Failure != "" {
		source, state = vpn.AccessFail, "TCP 建立失败"
		reason := map[string]string{"dns": "DNS 解析失败", "alias": "域名映射过期或无效", "denied": "目标或端口未授权", "canceled": "连接已取消或会话结束", "timeout": "连接超时", "refused": "目标拒绝连接", "unreachable": "目标网络不可达", "connect": "连接未建立", "busy": "连接核心繁忙"}[r.Failure]
		if reason != "" {
			state += "：" + reason
		}
		if r.Route == "vpn" || r.Route == "direct" {
			path = "尝试 " + path
		}
	}
	line := fmt.Sprintf("本机软件：%s → %s ｜ %s ｜ %s", logField(e.Name), logField(target), path, state)
	if rule != "" {
		line += " ｜ " + rule
	}
	return source, line
}

func logField(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			return ' '
		}
		return r
	}, s)
	runes := []rune(s)
	if len(runes) > 256 {
		s = string(runes[:256]) + "…"
	}
	return s
}
