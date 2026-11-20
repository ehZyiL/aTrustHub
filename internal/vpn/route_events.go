package vpn

import (
	"context"
	"errors"
	"fmt"
	"github.com/qy/easyconnect/internal/routing"
	"net"
	"strings"
	"time"
)

type RouteEvent struct {
	Entry, Target, Protocol, RuleID, Reason string
	Planned, Actual, Stage, Version         string
	Generation, Attempt                     int
	Elapsed                                 time.Duration
}

func (e RouteEvent) Detail() string {
	return fmt.Sprintf("入口：%s\n目标：%s / %s\n规则：%s\n决定：%s\n计划出口：%s\n实际出口：%s\n阶段：%s\n尝试：%d · 耗时：%s\n会话代次：%d · 资源版本：%s", e.Entry, e.Target, e.Protocol, e.RuleID, e.Reason, e.Planned, e.Actual, e.Stage, e.Attempt, e.Elapsed.Round(time.Millisecond), e.Generation, e.Version)
}

func (m *Manager) logRoute(r routing.Request, d routing.Decision, c routedSession, attempt int, elapsed time.Duration, err error) {
	if m.bus == nil {
		return
	}
	e := RouteEvent{Entry: r.Entry, Target: d.Target, Protocol: r.Network, RuleID: d.RuleID, Reason: d.Reason, Planned: strings.Join(d.Owners, ","), Generation: c.gen, Version: c.version, Attempt: attempt, Elapsed: elapsed, Stage: "tcp_established"}
	source := AccessOK
	if e.RuleID == "" {
		var rules []string
		for _, match := range d.Matches {
			if c.id == "" || match.GatewayID == c.id {
				rules = append(rules, match.GatewayID+"/"+match.Source)
			}
		}
		e.RuleID = strings.Join(rules, "; ")
		if e.RuleID == "" {
			e.RuleID = "未命中受管规则"
		}
	}
	if err != nil {
		source = AccessFail
		e.Stage = "connect"
		if d.Action == "blocked" {
			e.Stage = "policy"
		} else if errors.Is(err, context.Canceled) {
			e.Stage = "canceled"
		} else if errors.Is(err, context.DeadlineExceeded) {
			e.Stage = "timeout"
		} else if errors.Is(err, net.ErrClosed) {
			e.Stage = "session_changed"
		}
	} else if d.Action == "direct" {
		e.Actual = "原网络"
	} else {
		e.Actual = c.id
	}
	status := "TCP 已建立"
	if err == nil && (r.Network == "udp" || r.Network == "udp4") {
		e.Stage = "udp_ready"
		status = "UDP 通道已就绪 · 尚未验证应答"
	}
	if err != nil {
		status = "连接未建立 · " + e.Stage
	}
	exit := e.Actual
	if exit == "" {
		exit = e.Planned
	}
	if exit == "" {
		exit = "无出口"
	}
	m.bus.upsertRoute(source, fmt.Sprintf("%s → %s ｜ %s ｜ %s", e.Target, exit, status, e.Reason), e)
}

// ResourceGateways returns read-only copies, including offline attribution.
func (m *Manager) ResourceGateways() []routing.Gateway {
	gateways, _, _ := m.routeSnapshot("")
	for i := range gateways {
		gateways[i].Current = cloneResources(gateways[i].Current)
		gateways[i].Known = cloneResources(gateways[i].Known)
	}
	return gateways
}
