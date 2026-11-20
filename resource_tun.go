package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"

	"github.com/egoist/mygo/ui"
	"github.com/qy/easyconnect/internal/dnsmapping"
	"github.com/qy/easyconnect/internal/localapps"
	"github.com/qy/easyconnect/internal/vpn"
	"github.com/qy/easyconnect/internal/workeripc"
)

func (a *app) resourceTUNActive() bool {
	if a.resourceTUN == nil {
		return false
	}
	v := a.resourceTUN.View()
	return v.Running || v.Busy || v.CleanupPending
}

func (a *app) setupResourceTUN() {
	if !supportsResourceTUN() || a.resourceTUN != nil || a.local == nil {
		return
	}
	var notifyMu sync.Mutex
	lastMessage := ""
	a.resourceTUN = &resourceTUNController{configs: a.resourceCaptureConfigs,
		start: func(ctx context.Context, configs []localapps.CaptureConfig) (localapps.SystemCapture, error) {
			return a.local.StartSystemCapture(ctx, configs, func(ctx context.Context, network, address string) (net.Conn, error) {
				if network == "udp4" {
					return a.mgr.DialCapturedUDP(ctx, address)
				}
				return a.mgr.DialCaptured(ctx, network, address)
			})
		},
		suspendProxy: func() (func() error, error) {
			_, port, err := net.SplitHostPort(a.mgr.Aggregate().Addr)
			if err != nil {
				port = "0"
			}
			return suspendProxyForResourceTUN(a.dir, net.JoinHostPort("127.0.0.1", port), func(message string) {
				if a.bus != nil {
					a.bus.Add("app", message)
				}
			})
		}, change: func() {
			view := a.resourceTUN.View()
			message := view.Error
			if message == "" && view.Running {
				message = "系统 TUN 已就绪：IPv4 TCP + DNS，复用在线 VPN 会话"
			}
			if message == "" && !view.Busy {
				message = "系统 TUN 已停止"
			}
			notifyMu.Lock()
			changed := message != "" && message != lastMessage
			lastMessage = message
			notifyMu.Unlock()
			if changed && a.bus != nil {
				a.bus.Add("app", message)
			}
			if a.win != nil {
				a.win.Invalidate()
			}
		}}
}

func (a *app) resourceCaptureConfigs() ([]localapps.CaptureConfig, error) {
	cfg := a.store.Config()
	var result []localapps.CaptureConfig
	online := 0
	for _, gateway := range a.mgr.ResourceGateways() {
		if gateway.Excluded {
			continue
		}
		point := cfg.Find(gateway.ID)
		if point == nil {
			continue
		}
		var connection vpn.AppConnection
		if gateway.Online {
			if !gateway.Strict {
				return nil, fmt.Errorf("%s 不支持严格 VPN 拨号", gateway.Name)
			}
			var err error
			connection, err = a.mgr.LocalAppConnection(gateway.ID)
			if err != nil {
				return nil, err
			}
			online++
		} else {
			if gateway.Known == nil {
				continue
			}
			// Offline records install capture guards only. DNS and business
			// authorization still come from Manager, which rejects this owner.
			key := fmt.Sprintf("guard/%s/%d/%s", gateway.ID, gateway.Generation, gateway.Version)
			connection = vpn.AppConnection{Key: key, Identity: dnsmapping.Identity{Key: key, GatewayID: gateway.ID, Generation: gateway.Generation, Version: gateway.Version}, Resources: gateway.Known, Active: func() bool { return true }, SelectDNS: a.mgr.SelectMappedDNS,
				MappedDNS: func(context.Context, []byte, string) (workeripc.Message, error) {
					return workeripc.Message{}, net.ErrClosed
				},
				BeginPublication: func(string) (func(), error) { return nil, net.ErrClosed }, ConfirmAliases: func([]workeripc.DNSAlias) error { return net.ErrClosed }}
		}
		domains, err := localapps.DNSDomains(connection.Resources)
		if err != nil {
			return nil, fmt.Errorf("%s：%w", gateway.Name, err)
		}
		networks, err := localapps.CaptureNetworks(connection.Resources)
		if err != nil {
			return nil, fmt.Errorf("%s：%w", gateway.Name, err)
		}
		if len(domains) == 0 && len(networks) == 0 {
			continue
		}
		result = append(result, localapps.CaptureConfig{Key: connection.Key, Identity: connection.Identity, Guard: !gateway.Online, Gateway: point.Server, Domains: domains, Networks: networks,
			Exchange: connection.DNS, MappedDNS: connection.MappedDNS, SelectDNS: connection.SelectDNS, BeginPublication: connection.BeginPublication, CheckPublication: connection.CheckPublication, MappingPrefix: connection.MappingPrefix, ConfirmAliases: connection.ConfirmAliases,
			ReservedPools: connection.ReservedPools, AliasNetworks: connection.AliasNetworks, Active: connection.Active})
	}
	running := a.resourceTUN != nil && a.resourceTUN.View().Running
	if online == 0 && !running {
		return nil, errors.New("请先登录至少一个加入统一资源池的网关")
	}
	if len(result) == 0 {
		return nil, errors.New("没有可接管的网络资源")
	}
	return result, nil
}

func supportsResourceTUN() bool { return runtime.GOOS == "windows" || runtime.GOOS == "linux" }

// captureStatus 是应用接管的状态行：下拉负责开关，这里只报状态与修正入口。
func (a *app) captureStatus(c *ui.Context) {
	if !supportsResourceTUN() {
		return
	}
	t := c.Theme()
	status := resourceTUNStatus{}
	if a.resourceTUN != nil {
		status = a.resourceTUN.View()
	}
	switch {
	case status.Running:
		ui.Text(c, "应用接管：已接管 IPv4 TCP + DNS（UDP 试验）").
			FontSize(13).TextColor(t.Success)
	case status.Busy:
		ui.Text(c, "应用接管：处理中…").FontSize(13).TextColor(t.Warning)
	case status.CleanupPending:
		ui.Text(c, "应用接管：上次的清理还没完成").FontSize(13).TextColor(t.Warning)
	case status.Error != "":
		ui.Text(c, "应用接管：需检查").FontSize(13).TextColor(t.Danger).
			Tooltip(status.Error)
	default:
		ui.Text(c, "应用接管：未启用").FontSize(13).TextColor(t.TextMuted)
	}
	ui.Row(c).Gap(8).AlignItems(ui.Center).Wrap().Children(func() {
		if status.Error != "" && ui.Button(c, "查看失败原因").FontSize(11).Clicked() {
			a.toast = status.Error
		}
		if status.Busy && a.resourceTUN != nil && ui.Button(c, "取消接管").FontSize(11).Clicked() {
			a.resourceTUN.Stop()
		}
		if status.CleanupPending && a.resourceTUN != nil && ui.Button(c, "重试清理").FontSize(11).Clicked() {
			a.resourceTUN.Stop()
		}
		if ui.Button(c, "接管日志").FontSize(11).Clicked() {
			a.openTUNLog()
		}
	})
}
