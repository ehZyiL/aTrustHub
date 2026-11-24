package main

import (
	"strings"

	"github.com/egoist/mygo/ui"

	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/ehzyil/connect-hub/internal/relay"
)

// relayImportDraft is the 同事分享 import panel. Preview is local: parsing and
// rendering never touch the network. Only "添加并连接" contacts the host.
type relayImportDraft struct {
	open   bool
	text   string
	code   relay.ShareCode
	parsed bool
	name   string
	err    string
	busy   bool
}

// openRelayImport opens the import panel. It does not read the clipboard: that is
// a separate opt-in feature.
func (a *app) openRelayImport() {
	a.relayImport = relayImportDraft{open: true}
	a.invalidate()
}

func (a *app) relayImportView(c *ui.Context) {
	d := &a.relayImport
	if !d.open {
		return
	}
	t := c.Theme()
	ui.Modal(c, &d.open, func() {
		ui.Column(c).Width(dialogRegular).Gap(10).Children(func() {
			dialogHeader(c, "导入同事分享", "VPN 资源走共享主机，公网走本机")
			ui.Scroll(c).MaxHeight(a.dialogBodyMaxHeight()).MinHeight(0).
				ScrollbarInsets(4, 2, 4, 0).Children(func() {
				ui.Column(c).Padding(0, 14, 8, 0).Gap(10).Children(func() {
					ui.Field(c, "分享口令", func() {
						if ui.TextArea(c, &d.text).Placeholder("粘贴以 connect-hub://relay/v1# 开头的口令").Changed() {
							a.parseRelayImport()
						}
					})
					ui.Text(c, "预览只在本机解析，不会联网；点击添加后才验证对端证书和口令。").
						FontSize(11).TextColor(t.TextMuted).Wrap()
					if d.parsed {
						ui.Column(c).Gap(6).Children(func() {
							ui.Row(c).Gap(8).Children(func() {
								ui.Text(c, "名称").FontSize(12).TextColor(t.TextMuted).Width(96)
								ui.Text(c, orDash(d.code.DisplayName())).FontSize(12).Wrap()
							})
							ui.Row(c).Gap(8).Children(func() {
								ui.Text(c, "地址").FontSize(12).TextColor(t.TextMuted).Width(96)
								ui.Text(c, d.code.Address()).FontSize(12).Wrap()
							})
							ui.Row(c).Gap(8).Children(func() {
								ui.Text(c, "指纹").FontSize(12).TextColor(t.TextMuted).Width(96)
								ui.Text(c, shortFingerprint(d.code.Fingerprint)).Font("monospace").FontSize(11).Wrap()
							})
							if exists := a.findRelayPoint(d.code); exists != nil {
								ui.Text(c, "已导入过同一分享："+exists.Name).FontSize(12).TextColor(t.Warning).Wrap()
							}
						})
					}
					if d.err != "" {
						ui.Text(c, d.err).FontSize(11).TextColor(t.Danger).Wrap()
					}
				})
			})
			dialogFooter(c, func() {
				if ui.Button(c, "取消").FontSize(11).Clicked() {
					d.open = false
				}
				ui.Row(c).Grow(1)
				if ui.PrimaryButton(c, "添加并连接").FontSize(11).
					Disabled(!d.parsed || d.busy).Clicked() {
					a.submitRelayImport()
				}
			})
		})
	})
}

func shortFingerprint(fp string) string {
	if len(fp) <= 16 {
		return fp
	}
	return fp[:16] + "…"
}

// parseRelayImport parses the pasted text locally.
func (a *app) parseRelayImport() {
	d := &a.relayImport
	d.err = ""
	d.parsed = false
	text := strings.TrimSpace(d.text)
	if text == "" {
		return
	}
	code, err := relay.ParseShareCode(text)
	if err != nil {
		d.err = "无法识别的分享口令：" + strings.TrimPrefix(err.Error(), "不是分享口令: ")
		return
	}
	d.code = code
	d.parsed = true
}

// findRelayPoint locates an already imported share by fingerprint + share ID.
// Equal names never mean the same node.
func (a *app) findRelayPoint(code relay.ShareCode) *model.AccessPoint {
	for i := range a.cfg.Points {
		p := &a.cfg.Points[i]
		if p.Protocol != model.ProtocolLANRelay || p.Relay == nil {
			continue
		}
		if p.Relay.ShareID == code.ShareID && p.Relay.CertificateSHA256 == code.Fingerprint {
			return p
		}
	}
	return nil
}

// submitRelayImport stores the node and connects once. Storage order follows the
// contract: validate, mint an id, write the secret, update, save, apply, connect.
// A failure rolls back the in-memory change and the secret it created.
func (a *app) submitRelayImport() {
	d := &a.relayImport
	if !d.parsed {
		return
	}
	if existing := a.findRelayPoint(d.code); existing != nil {
		d.err = "这条分享已经导入为「" + existing.Name + "」，无需重复添加"
		a.invalidate()
		return
	}
	name := strings.TrimSpace(d.code.Name)
	if name == "" {
		name = "同事分享 " + d.code.Host
	}
	point := model.AccessPoint{
		ID:        model.NewID(),
		Name:      name,
		Protocol:  model.ProtocolLANRelay,
		Server:    d.code.Host,
		Port:      d.code.Port,
		InPool:    true,
		SocksPort: 0,
		// A new node never logs in at startup: importing and auto-connecting
		// are separate decisions.
		AutoConnect: false,
		Relay: &model.RelayPointOptions{
			Version:           d.code.Version,
			ShareID:           d.code.ShareID,
			CertificateSHA256: d.code.Fingerprint,
		},
	}
	point.Normalize()
	if err := point.Validate(); err != nil {
		d.err = err.Error()
		a.invalidate()
		return
	}
	if err := a.store.SetPassword(point.ID, d.code.Token); err != nil {
		d.err = "分享口令无法安全保存：" + err.Error()
		a.invalidate()
		return
	}
	if _, err := a.store.Update(func(cfg *model.Config) error {
		cfg.Add(point)
		return nil
	}); err != nil {
		_ = a.store.SetPassword(point.ID, "")
		d.err = err.Error()
		a.invalidate()
		return
	}
	if err := a.store.Save(); err != nil {
		// Roll the memory change back and drop the secret this import created.
		_, _ = a.store.Update(func(cfg *model.Config) error {
			cfg.Remove(point.ID)
			return nil
		})
		_ = a.store.SetPassword(point.ID, "")
		d.err = "配置保存失败：" + err.Error()
		a.invalidate()
		return
	}
	cfg := a.store.Config()
	a.setConfig(cfg)
	a.mgr.Apply(cfg)
	d.open = false
	a.toast = "已添加「" + point.Name + "」，正在连接共享主机"
	// Importing does not take over the system proxy by itself.
	go a.mgr.Connect(point.ID)
	a.invalidate()
}
