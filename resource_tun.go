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
	"github.com/qy/easyconnect/internal/model"
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
	if runtime.GOOS != "windows" || a.resourceTUN != nil || a.local == nil {
		return
	}
	var notifyMu sync.Mutex
	lastMessage := ""
	a.resourceTUN = &resourceTUNController{configs: a.resourceCaptureConfigs,
		start: func(ctx context.Context, configs []localapps.CaptureConfig) (localapps.SystemCapture, error) {
			return a.local.StartSystemCapture(ctx, configs, a.mgr.DialCaptured)
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
		result = append(result, localapps.CaptureConfig{Key: connection.Key, Identity: connection.Identity, Gateway: point.Server, Domains: domains, Networks: networks,
			Exchange: connection.DNS, MappedDNS: connection.MappedDNS, SelectDNS: connection.SelectDNS, BeginPublication: connection.BeginPublication, ConfirmAliases: connection.ConfirmAliases,
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

func (a *app) resourceTUNControls(c *ui.Context) {
	if runtime.GOOS != "windows" {
		return
	}
	status := resourceTUNStatus{}
	if a.resourceTUN != nil {
		status = a.resourceTUN.View()
	}
	ui.Row(c).Gap(6).AlignItems(ui.Center).Children(func() {
		label := "系统 TUN (TCP)"
		if status.Running {
			label = "关闭系统 TUN"
		} else if status.Busy {
			label = "系统 TUN 处理中…"
		}
		if status.Busy && a.resourceTUN != nil {
			if ui.Button(c, "取消").Clicked() {
				a.resourceTUN.Stop()
			}
		}
		if status.CleanupPending && a.resourceTUN != nil {
			if ui.Button(c, "重试清理").Clicked() {
				a.resourceTUN.Stop()
			}
		}
		if ui.Button(c, label).Disabled(status.Busy || status.CleanupPending || a.tunOn || a.tunPending).Clicked() {
			a.setupResourceTUN()
			if a.resourceTUN != nil {
				if status.Running {
					a.resourceTUN.Stop()
				} else {
					a.tunWanted = false
					if a.store != nil {
						_, err := a.store.Update(func(cfg *model.Config) error { cfg.Settings.TunEnabled = false; return nil })
						if err == nil {
							err = a.saveConfig()
						}
						if err != nil {
							a.toast = "保存接管模式失败：" + err.Error()
							return
						}
					}
					a.resourceTUN.Start()
				}
			}
		}
		if status.Running {
			ui.Text(c, "IPv4 TCP + DNS").FontSize(11).TextColor(c.Theme().TextMuted)
		}
		if status.Running || status.Error != "" {
			ui.Row(c).Padding(5).OnClick(func() { a.logsOpen = true }).Tooltip("系统 TUN 与访问日志").Children(func() { ui.Icon(c, logIcon).Size(16, 16) })
		}
		if status.Error != "" {
			ui.Text(c, "接管状态需检查").TextColor(c.Theme().Danger).Tooltip(status.Error)
			if ui.Button(c, "详情").Clicked() {
				a.toast = status.Error
			}
		}
	})
}
