package desktop

import (
	"github.com/egoist/mygo/ui"
	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/ehzyil/connect-hub/internal/vpn"
	"strconv"
	"strings"
)

type editorDraft struct {
	protocol               string
	healthTarget           string
	remoteDNS              string
	internalDomains        string
	certificateSHA256      string
	certificateToken       string
	certificateAddress     string
	certificateAcceptedPin string
	advanced               bool
	detailsOpen            bool
	open                   bool
	editingID              string
	name                   string
	address                string
	username               string
	authMode               string
	authModeLabel          string
	cred                   string
	totp                   string
	domain                 string
	socksPort              string
	inPool                 bool
	autoConnect            bool
	// autoPick lets detection choose the auth mode: what a point saved by an
	// older version (mode "auto") gets when it is opened.
	autoPick     bool
	monitor      bool
	monitorEvery string
	secretStore  string
	clearTOTP    bool
	hasPassword  bool
	hasTOTP      bool
	detected     []string
	detecting    bool
	detectGen    int
	detectErr    string
	err          string
}

func authModeLabels() []string {
	out := make([]string, 0, len(model.AuthModeLabels))
	for _, entry := range model.AuthModeLabels {
		out = append(out, entry.Label)
	}
	return out
}

func authModeFromLabel(label string) model.AuthMode {
	for _, entry := range model.AuthModeLabels {
		if entry.Label == label {
			return entry.Value
		}
	}
	// The editor no longer offers "自动识别", so an unknown label falls back
	// to the mode that needs the least explanation.
	return model.AuthModePassword
}

func (a *app) editorView(c *ui.Context) {
	if !a.editor.open {
		return
	}
	t := c.Theme()
	d := &a.editor
	ui.Modal(c, &d.open, func() {
		ui.Column(c).Width(dialogWide).Gap(10).Children(func() {
			dialogHeader(c, editorTitle(d), editorSubtitle(d))
			ui.Scroll(c).MaxHeight(a.dialogBodyMaxHeight()).MinHeight(0).
				ScrollbarInsets(4, 2, 4, 0).Children(func() {
				ui.Column(c).Padding(0, 14, 8, 0).Gap(10).Children(func() {
					if v, ok := a.mgr.View(d.editingID); ok {
						a.pointTools(c, v)
					}
					ui.Field(c, "VPN 协议", func() { ui.Select(c, &d.protocol, []string{"EasyConnect", "aTrust"}) })
					ui.Field(c, "名称", func() {
						ui.TextInput(c, &d.name).Placeholder("例如：主网关 / 教育网线路")
					})
					// 接入地址先填，检测按钮紧跟着它，点检测时地址已经在上方。
					ui.Field(c, "接入地址", func() {
						ui.TextInput(c, &d.address).
							Placeholder("例如：https://vpn.example.com:443").Grow(1)
					})
					if d.protocol == "EasyConnect" {
						d.authMode, d.authModeLabel = string(model.AuthModePassword), model.AuthModePassword.Label()
						ui.Field(c, "用户名", func() { ui.TextInput(c, &d.username) })
						ui.Field(c, "密码", func() {
							input := ui.TextInput(c, &d.cred).Password()
							if d.hasPassword {
								input.Placeholder("已保存，留空则沿用")
							}
						})
						ui.Text(c, "短信、动态口令或图形验证码会在连接时弹出。无需保存动态口令密钥。").FontSize(11).TextColor(t.TextMuted).Wrap()
						ui.Checkbox(c, &d.advanced, "高级：内网 DNS、保活目标与证书兼容")
						if d.advanced {
							ui.Field(c, "保活探测目标（可选，URL 或 host:port）", func() {
								ui.TextInput(c, &d.healthTarget).Placeholder("如 192.168.132.16:9011 或 http://oa:8080/，留空按原逻辑自动探测")
							})
							ui.Field(c, "VPN DNS（可选，IPv4）", func() { ui.TextInput(c, &d.remoteDNS).Placeholder("留空使用网关下发的 DNS") })
							ui.Field(c, "内网域名后缀（可选，逗号分隔）", func() { ui.TextInput(c, &d.internalDomains).Placeholder("例如：corp.example.com") })
							ui.Field(c, "网关证书 SHA256（可选）", func() {
								ui.TextInput(c, &d.certificateSHA256).Placeholder("可点击下方按钮读取，无需手工查找")
							})
							if ui.Button(c, "读取网关证书…").FontSize(11).Clicked() {
								a.openEditorCertificate()
							}
							ui.Text(c, "读取后展示证书信息，由你确认是否信任；只对当前接入点生效。").FontSize(11).TextColor(t.TextMuted).Wrap()
						}
					} else {
						ui.Row(c).Gap(10).AlignItems(ui.End).Children(func() {
							ui.Field(c, "认证方式", func() {
								ui.Select(c, &d.authModeLabel, authModeLabels()).Width(220)
								d.authMode = string(authModeFromLabel(d.authModeLabel))
							})
							if ui.Button(c, "检测").FontSize(11).Disabled(d.detecting).Clicked() {
								a.detectEditor()
							}
						})
						if d.detecting {
							ui.Row(c).Gap(6).AlignItems(ui.Center).Children(func() {
								ui.Spinner(c)
								ui.Text(c, "正在读取服务器支持的认证方式…").FontSize(11).TextColor(t.TextMuted)
							})
						}
						if d.detectErr != "" {
							ui.Text(c, d.detectErr).FontSize(11).TextColor(t.Danger)
						}
						if len(d.detected) > 0 {
							ui.Text(c, "服务器支持："+strings.Join(d.detected, "、")).FontSize(11).
								TextColor(t.TextMuted)
						}
						switch d.authMode {
						case string(model.AuthModeWeCom):
							// 企业微信：登录域用来在服务器提供多个外部登录时挑一个。
							ui.Field(c, "登录域（可选）", func() {
								ui.TextInput(c, &d.domain).Placeholder("服务器有多个外部登录方式时用来区分").Width(240)
							})
						case string(model.AuthModeSSO):
							// 单点登录：账号密码在对方页面上完成，这里只说明流程。
							ui.Text(c, "保存后点卡片上的「登录」会打开浏览器完成单点登录，"+
								"登录成功后自动取回会话并连接。").
								FontSize(11).TextColor(t.TextMuted)
						default:
							ui.Field(c, "用户名", func() {
								ui.TextInput(c, &d.username).Placeholder("登录 aTrust 的账号")
							})
							ui.Row(c).Gap(10).AlignItems(ui.End).Children(func() {
								ui.Field(c, "密码", func() {
									in := ui.TextInput(c, &d.cred).Password().Grow(1)
									if d.hasPassword {
										in.Placeholder("已保存，留空则沿用")
									} else {
										in.Placeholder("登录密码")
									}
								})
								ui.Field(c, "登录域", func() {
									ui.TextInput(c, &d.domain).Placeholder("默认 Radius").Width(180)
								})
							})
							ui.Field(c, "TOTP 密钥（可选）", func() {
								ui.TextInput(c, &d.totp).Placeholder("Base32 密钥，留空则不用动态口令")
							})
							if d.hasTOTP {
								ui.Checkbox(c, &d.clearTOTP, "清除已保存的 TOTP 密钥")
							}
						}
					}
					ui.Field(c, "密码存储方式", func() {
						ui.Select(c, &d.secretStore, secretStoreLabels()).Width(220)
					})
					ui.Text(c, "系统凭据服务不可用时仅在本次运行保存，重启后需重新填写。").FontSize(11).TextColor(t.TextMuted).Wrap()
					ui.Divider(c)
					ui.Row(c).Gap(14).AlignItems(ui.Start).Children(func() {
						// 简单模式下这两个字段被锁定（一个代理地址），不再展示：
						// 看得见却改不了比看不见更糟。
						if !a.simpleMode() {
							ui.Field(c, "独立 SOCKS5 端口", func() {
								ui.TextInput(c, &d.socksPort).Width(100)
							})
						}
						// The boxes follow the field's own rhythm: the first lines up
						// with the port caption, the next with the input under it.
						ui.Column(c).Gap(9).Children(func() {
							if !a.simpleMode() {
								ui.Checkbox(c, &d.inPool, "加入统一入口分流")
							}
							ui.Checkbox(c, &d.autoConnect, "应用启动时自动登录")
						})
					})
					if d.protocol != "EasyConnect" {
						ui.Row(c).Gap(14).AlignItems(ui.Center).Children(func() {
							ui.Checkbox(c, &d.monitor, "监测会话是否仍有效")
							if d.monitor {
								// Label and box on one line: the stacked field wrapped the
								// caption onto two lines and looked out of place here.
								ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
									ui.Text(c, "监测间隔（秒）").FontSize(13)
									ui.TextInput(c, &d.monitorEvery).Width(90)
								})
							}
						})
					}
					if d.err != "" {
						ui.Text(c, d.err).FontSize(11).TextColor(t.Danger)
					}
				})
			})
			// 底部：删除在左，取消与保存在右。
			dialogFooter(c, func() {
				if d.editingID == "" {
					// The other source of an access point: a LAN relay node
					// imported from a colleague's share code.
					if ui.Button(c, "导入同事分享…").FontSize(11).Clicked() {
						d.open = false
						a.openRelayImport()
					}
				}
				if d.editingID != "" {
					if ui.Button(c, "删除此接入点").FontSize(11).Background(t.Danger).
						TextColor(t.AccentText).
						Label("删除接入点 " + d.name).Clicked() {
						a.deleting = d.editingID
						d.open = false
					}
				}
				ui.Row(c).Grow(1)
				if ui.Button(c, "取消").FontSize(11).Clicked() {
					d.open = false
				}
				if ui.PrimaryButton(c, "保存").Label("保存接入点").FontSize(11).Clicked() {
					a.saveEditor()
				}
			})
		})
	})
}

func (a *app) pointTools(c *ui.Context, v vpn.View) {
	t := c.Theme()
	if v.State == vpn.StateError && v.Error != "" {
		ui.Text(c, v.Error).FontSize(12).TextColor(t.Danger).Wrap()
	}
	if v.Protocol == model.ProtocolEasyConnect && vpn.IsGatewayCertificateError(v.Error) {
		if ui.Button(c, "查看网关证书").Label("查看网关证书 " + v.Name).FontSize(12).Clicked() {
			a.openEditorCertificate()
		}
	}
	if v.State != vpn.StateOnline {
		return
	}
	ui.Column(c).Padding(10, 12).Gap(6).Radius(8).Background(t.Background).Children(func() {
		ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
			ui.Text(c, "连接详情").FontSize(13).Bold().Grow(1)
			label := "查看详情"
			if a.editor.detailsOpen {
				label = "收起详情"
			}
			if ui.Button(c, label).FontSize(12).Clicked() {
				a.editor.detailsOpen = !a.editor.detailsOpen
			}
		})
		if !a.editor.detailsOpen {
			return
		}
		pointAlerts(c, v)
		a.pointFacts(c, v)
		ui.Row(c).GapX(8).GapY(6).AlignItems(ui.Center).Wrap().Children(func() {
			if v.SocksPort > 0 && !a.simpleMode() {
				addr := "127.0.0.1:" + strconv.Itoa(v.SocksPort)
				metaCopy(c, t, "HTTP / SOCKS5", addr, "复制独立 SOCKS5 地址",
					func() { a.copyText("socks5://" + addr) })
			}
			if v.Protocol == model.ProtocolEasyConnect && ui.Button(c, "DNS 诊断").Label("DNS 诊断 "+v.Name).FontSize(12).Clicked() {
				a.openDNSProbe(v.ID, v.Name)
			}
			if v.Protocol == model.ProtocolLANRelay && ui.Button(c, "连接诊断").Label("连接诊断 "+v.Name).FontSize(12).Clicked() {
				a.openRelayDiagnose(v.ID)
			}
			if v.Protocol != model.ProtocolLANRelay && a.lanShare != nil &&
				ui.Button(c, "局域网分享").Label("局域网分享 "+v.Name).FontSize(12).Clicked() {
				a.openLANShareFor(v.ID)
			}
			if v.MonitorOn {
				iconButton(c, refreshIcon, "立即检测会话是否仍有效", func() {
					if a.mgr.CheckNow(v.ID) {
						a.setToast("已发起会话有效性检测")
					} else {
						a.setToast("只有在线的接入点可以检测")
					}
				})
			}
			if a.canLogout(a.cfg.Find(v.ID)) && ui.Button(c, "退出登录").Label("退出登录 "+v.Name).FontSize(12).Clicked() {
				a.askLogout(v)
			}
		})
	})
}

func editorSubtitle(d *editorDraft) string {
	if d.editingID == "" {
		return "填好服务器地址与登录方式，保存后回到接入点卡片点「登录」"
	}
	return "改动会在下次登录时生效；需要重新认证的项目请一并更新"
}

func editorTitle(d *editorDraft) string {
	if d.editingID == "" {
		return "添加接入点"
	}
	return "编辑接入点"
}

func protocolLabel(value string) string {
	switch value {
	case model.ProtocolEasyConnect:
		return "EasyConnect"
	case model.ProtocolLANRelay:
		// A relay node is not an aTrust gateway; labelling it as one would put
		// it in the wrong group and misstate where traffic goes.
		return "局域网中继"
	}
	return "aTrust"
}

func protocolFromLabel(label string) string {
	if label == "EasyConnect" {
		return model.ProtocolEasyConnect
	}
	return model.ProtocolATrust
}
