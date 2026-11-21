package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/ehZyiL/connect-hub/internal/model"
	"github.com/ehZyiL/connect-hub/internal/vpn"
	"github.com/ehZyiL/connect-hub/internal/workeripc"
)

type certificateProbeReply struct {
	info *workeripc.CertificateInfo
	err  error
}

type certificateProbeDraft struct {
	open, running, confirmed   bool
	name, pointID, editorToken string
	server, previousPin        string
	port                       int
	info                       *workeripc.CertificateInfo
	err                        string
	cancel                     context.CancelFunc
	replies                    <-chan certificateProbeReply
}

func (a *app) openGatewayCertificate(id string) {
	p := a.cfg.Find(id)
	if p == nil || p.Protocol != model.ProtocolEasyConnect {
		return
	}
	a.openCertificateProbe(certificateProbeDraft{name: p.Name, pointID: p.ID, server: p.Server, port: p.Port, previousPin: p.CertificateSHA256})
}

func (a *app) openEditorCertificate() {
	d := &a.editor
	server, port, err := model.ParseAccessAddress(d.address)
	if err != nil {
		d.err = err.Error()
		return
	}
	a.openCertificateProbe(certificateProbeDraft{name: d.name, editorToken: d.certificateToken, server: server, port: port, previousPin: d.certificateSHA256})
}

func (a *app) openCertificateProbe(d certificateProbeDraft) {
	if a.certificateProbe.cancel != nil {
		a.certificateProbe.cancel()
	}
	d.open = true
	a.certificateProbe = d
	a.startCertificateProbe()
}

func (a *app) startCertificateProbe() {
	d := &a.certificateProbe
	if d.cancel != nil {
		d.cancel()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	replies := make(chan certificateProbeReply, 1)
	d.cancel, d.replies, d.running = cancel, replies, true
	d.info, d.err, d.confirmed = nil, "", false
	server, port := d.server, d.port
	go func() {
		defer cancel()
		info, err := vpn.ProbeGatewayCertificate(ctx, server, port)
		replies <- certificateProbeReply{info, err}
		a.invalidate()
	}()
}

func normalizeCertificatePin(pin string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(pin), ":", ""))
}

func (d *certificateProbeDraft) changed() bool {
	return d.info != nil && normalizeCertificatePin(d.previousPin) != "" && normalizeCertificatePin(d.previousPin) != normalizeCertificatePin(d.info.SHA256)
}

func (d *certificateProbeDraft) checkApproval(server string, port int, pin string) error {
	if !d.open || d.running || !d.confirmed || !vpn.ValidCertificateInfo(d.info) {
		return errors.New("请先读取证书并确认信任")
	}
	if server != d.server || port != d.port || normalizeCertificatePin(pin) != normalizeCertificatePin(d.previousPin) {
		return errors.New("接入地址或已信任证书已改变，请关闭弹窗后重新读取")
	}
	return nil
}

func (d *certificateProbeDraft) applyToEditor(editor *editorDraft) error {
	server, port, err := model.ParseAccessAddress(editor.address)
	if err != nil || !editor.open || editor.protocol != "EasyConnect" || d.editorToken == "" || d.editorToken != editor.certificateToken {
		return errors.New("编辑对象已改变，请重新读取证书")
	}
	if err := d.checkApproval(server, port, editor.certificateSHA256); err != nil {
		return err
	}
	editor.certificateSHA256 = normalizeCertificatePin(d.info.SHA256)
	editor.certificateAddress = net.JoinHostPort(server, strconv.Itoa(port))
	editor.certificateAcceptedPin = editor.certificateSHA256
	return nil
}

func (d *certificateProbeDraft) applyToConfig(cfg *model.Config) error {
	p := cfg.Find(d.pointID)
	if p == nil || p.Protocol != model.ProtocolEasyConnect || d.editorToken != "" {
		return errors.New("接入点已改变，请重新读取证书")
	}
	if err := d.checkApproval(p.Server, p.Port, p.CertificateSHA256); err != nil {
		return err
	}
	p.CertificateSHA256 = normalizeCertificatePin(d.info.SHA256)
	return nil
}

func (d *editorDraft) checkCertificateAddress(server string, port int) error {
	if d.protocol == "EasyConnect" && d.certificateAddress != "" && normalizeCertificatePin(d.certificateSHA256) != "" &&
		normalizeCertificatePin(d.certificateSHA256) == normalizeCertificatePin(d.certificateAcceptedPin) && d.certificateAddress != net.JoinHostPort(server, strconv.Itoa(port)) {
		return errors.New("接入地址已改变，请重新读取并确认新网关证书，或清空原指纹")
	}
	return nil
}

func (a *app) acceptGatewayCertificate() {
	d := &a.certificateProbe
	if d.editorToken != "" {
		if err := d.applyToEditor(&a.editor); err != nil {
			d.err = err.Error()
			return
		}
		a.toast = "已填入证书指纹，保存接入点后生效"
	} else {
		v, ok := a.mgr.View(d.pointID)
		if !ok || v.State == vpn.StateOnline || v.State == vpn.StateConnecting {
			d.err = "接入点状态已改变，请先取消连接或断开后重新操作"
			return
		}
		if _, err := a.store.Update(d.applyToConfig); err != nil {
			d.err = err.Error()
			return
		}
		if err := a.saveConfig(); err != nil {
			// Failed persistence must not leave an unreported trust change in memory.
			_, _ = a.store.Update(func(cfg *model.Config) error {
				if p := cfg.Find(d.pointID); p != nil && p.CertificateSHA256 == normalizeCertificatePin(d.info.SHA256) {
					p.CertificateSHA256 = d.previousPin
				}
				return nil
			})
			d.err = "保存证书失败：" + err.Error()
			return
		}
		a.tunLogf("已更新「%s」的网关证书信任，准备重新连接", logField(d.name))
		a.mgr.Connect(d.pointID)
	}
	d.open = false
	if d.cancel != nil {
		d.cancel()
	}
}

func (a *app) certificateProbeView(c *ui.Context) {
	d := &a.certificateProbe
	if !d.open {
		return
	}
	if d.running {
		select {
		case reply := <-d.replies:
			d.running, d.info = false, reply.info
			if reply.err != nil {
				d.err = reply.err.Error()
			}
		default:
		}
	}
	ui.Modal(c, &d.open, func() {
		ui.Column(c).Width(dialogRegular).Gap(10).Children(func() {
			dialogHeader(c, "网关证书", d.name+" · "+model.FormatAccessAddress(d.server, d.port))
			ui.Text(c, "此操作只读取证书，不发送账号密码。指纹由程序计算，用于识别并记住这张证书。").
				FontSize(11).TextColor(c.Theme().TextMuted).Wrap()
			if d.running {
				ui.Text(c, "正在读取网关证书…").FontSize(11)
			}
			if info := d.info; info != nil {
				ui.Scroll(c).MaxHeight(230).Children(func() {
					ui.Column(c).Gap(7).Children(func() {
						ui.Text(c, "证书名称："+logField(info.Subject)).FontSize(13).Wrap()
						ui.Text(c, "颁发者："+logField(info.Issuer)).FontSize(13).Wrap()
						ui.Text(c, fmt.Sprintf("有效期：%s 至 %s", time.Unix(info.NotBefore, 0).Format("2006-01-02"), time.Unix(info.NotAfter, 0).Format("2006-01-02"))).FontSize(13).Wrap()
						ui.Text(c, "SHA256："+info.SHA256).Font("monospace").FontSize(11).Wrap()
						if info.MalformedSAN {
							ui.Text(c, "证书的域名字段格式不兼容；信任后将仅对这张证书启用兼容处理。").FontSize(13).TextColor(c.Theme().Warning).Wrap()
						}
						if now := time.Now().Unix(); now < info.NotBefore || now > info.NotAfter {
							ui.Text(c, "该证书当前不在有效期内，请向管理员核实。").FontSize(13).TextColor(c.Theme().Warning).Wrap()
						}
						if d.changed() {
							ui.Text(c, "证书已变更！请先向管理员核实是否换证，确认后才替换旧记录。").FontSize(13).TextColor(c.Theme().Danger).Wrap()
							ui.Text(c, "原 SHA256："+normalizeCertificatePin(d.previousPin)).Font("monospace").FontSize(11).Wrap()
						} else if d.previousPin != "" {
							ui.Text(c, "与已保存的证书指纹一致。").FontSize(13).Wrap()
						}
					})
				})
				ui.Text(c, "读取成功不代表来源已验证。首次信任前，请通过管理员或其他可信渠道核实；也可复制指纹请管理员确认。").FontSize(13).Wrap()
				label := "我已核实网关来源，信任此证书"
				if d.changed() {
					label = "我已核实此次证书变更，替换已信任证书"
				}
				ui.Checkbox(c, &d.confirmed, label)
			}
			if d.err != "" {
				ui.Text(c, d.err).FontSize(11).TextColor(c.Theme().Danger).Wrap()
			}
			dialogFooter(c, func() {
				if ui.Button(c, "取消").Label("取消证书读取").FontSize(11).Clicked() {
					d.open = false
				}
				if d.info != nil && ui.Button(c, "复制指纹").FontSize(11).Clicked() {
					a.copyText(d.info.SHA256)
				}
				ui.Row(c).Grow(1)
				if ui.Button(c, "重新读取").FontSize(11).Disabled(d.running).Clicked() {
					a.startCertificateProbe()
				}
				label := "信任并重试连接"
				if d.editorToken != "" {
					label = "信任并填入"
				}
				if ui.PrimaryButton(c, label).FontSize(11).
					Disabled(d.running || !d.confirmed || d.info == nil).Clicked() {
					a.acceptGatewayCertificate()
				}
			})
		})
	})
	if !d.open && d.cancel != nil {
		d.cancel()
	}
}
