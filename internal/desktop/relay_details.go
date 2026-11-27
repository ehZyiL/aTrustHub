package desktop

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/ehzyil/connect-hub/internal/model"
	relay "github.com/ehzyil/connect-hub/internal/relay/contract"
	"github.com/ehzyil/connect-hub/internal/vpn"
)

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
