package desktop

import (
	"errors"
	"fmt"
	"github.com/egoist/mygo/ui"
	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/ehzyil/connect-hub/internal/store"
	"github.com/ehzyil/connect-hub/internal/vpn"
)

func (a *app) deleteView(c *ui.Context) {
	if a.deleting == "" {
		return
	}
	t := c.Theme()
	var p *model.AccessPoint
	for i := range a.cfg.Points {
		if a.cfg.Points[i].ID == a.deleting {
			p = &a.cfg.Points[i]
			break
		}
	}
	open := a.deleting != ""
	ui.Modal(c, &open, func() {
		ui.Column(c).Width(dialogNarrow).Gap(10).Children(func() {
			dialogHeader(c, "删除接入点", "只影响这个接入点，其他配置不变")
			name := "这个接入点"
			if p != nil {
				name = "「" + p.Name + "」"
			}
			ui.Text(c, "删除 "+name+" 会断开它的登录，并删除保存的密码和 TOTP 密钥。").
				FontSize(13).TextColor(t.Text)
			dialogFooter(c, func() {
				ui.Row(c).Grow(1)
				if ui.Button(c, "取消").FontSize(11).Clicked() {
					a.deleting = ""
				}
				if ui.PrimaryButton(c, "确认删除").FontSize(11).Clicked() {
					a.removePoint(a.deleting)
					a.deleting = ""
				}
			})
		})
	})
	if !open {
		a.deleting = ""
	}
}

// canLogout reports whether "退出登录" is offered for a point: only a login
// that came from an external page leaves a session worth discarding by hand.
// That is the WeCom QR login, single sign-on, and the legacy "auto" mode —
// which, without a stored password, is the WeCom login too. A point that logs
// in with a password has nothing to discard, so it shows no such button.
func (a *app) canLogout(p *model.AccessPoint) bool {
	if p == nil {
		return false
	}
	switch model.AuthMode(p.AuthMode) {
	case model.AuthModeWeCom, model.AuthModeSSO:
		return true
	case model.AuthModeAuto:
		// 老配置的 auto：有密码就走密码，没有密码才落到企业微信。
		_, err := a.store.Password(p.ID)
		return errors.Is(err, store.ErrSecretNotFound)
	}
	return false
}

// askLogout refuses while the global TUN owns the session, then opens the
// confirmation: forgetting the authentication forces a new QR scan.
func (a *app) askLogout(v vpn.View) {
	if a.tunOn.Load() {
		for _, id := range splitIDs(a.tunPoints) {
			if id == v.ID {
				a.toast = "这个接入点正被全局 TUN 使用，先关闭 TUN 再退出登录"
				return
			}
		}
	}
	a.win.Update(func() { a.logoutAsk = v.ID })
}

// logoutView confirms forgetting a point's saved login.
func (a *app) logoutView(c *ui.Context) {
	if a.logoutAsk == "" {
		return
	}
	t := c.Theme()
	name := "这个接入点"
	var point *model.AccessPoint
	for i := range a.cfg.Points {
		if a.cfg.Points[i].ID == a.logoutAsk {
			name = "「" + a.cfg.Points[i].Name + "」"
			point = &a.cfg.Points[i]
		}
	}
	// 只有单点登录的会话存在浏览器里，才需要连浏览器数据一起清掉。
	usesBrowser := point != nil && model.AuthMode(point.AuthMode) == model.AuthModeSSO
	body := "退出 " + name + " 会清除本地暂存的认证信息，下次登录需要重新认证。"
	hint := "如果只是想暂时断开、稍后继续用同一个账号，点「断开」即可，" +
		"那样下次登录会直接复用这次认证，不用重新扫码。"
	if usesBrowser {
		body = "退出 " + name + " 会清除本地暂存的认证信息与浏览器登录数据（cookie），下次登录需要重新认证。"
		hint = "如果只是想暂时断开、稍后继续用同一个账号，点「断开」即可，" +
			"那样下次登录会直接复用这次认证，不会重新打开浏览器认证。"
	}
	open := a.logoutAsk != ""
	ui.Modal(c, &open, func() {
		ui.Column(c).Width(dialogNarrow).Gap(10).Children(func() {
			dialogHeader(c, "退出登录", body)
			ui.Text(c, hint).FontSize(11).TextColor(t.TextMuted).Wrap()
			dialogFooter(c, func() {
				ui.Row(c).Grow(1)
				if ui.Button(c, "取消").FontSize(11).Clicked() {
					a.logoutAsk = ""
				}
				if ui.Button(c, "确认退出登录").FontSize(11).Background(t.Danger).
					TextColor(t.AccentText).Clicked() {
					id := a.logoutAsk
					a.logoutAsk = ""
					go func() {
						a.mgr.Logout(id)
						// 企业微信的认证不在浏览器里，清配置目录反而会丢掉
						// 有用的东西；只有单点登录需要连浏览器会话一起清。
						if p := a.cfg.Find(id); p != nil && logoutClearsBrowser(model.AuthMode(p.AuthMode)) {
							a.clearBrowserLoginProfile(id)
						}
					}()
					a.toast = "已退出登录，下次登录需要重新认证"
				}
			})
		})
	})
	if !open {
		a.logoutAsk = ""
	}
}

// quitView asks before closing the app: quitting drops every tunnel and, with
// the global TUN on, restores the system DNS.
func (a *app) quitView(c *ui.Context) {
	if !a.quitAsk {
		return
	}
	t := c.Theme()
	open := a.quitAsk
	ui.Modal(c, &open, func() {
		ui.Column(c).Width(dialogNarrow).Gap(10).Children(func() {
			online, _, _ := a.mgr.Counts()
			line := "退出会断开所有隧道。"
			if a.tunOn.Load() {
				line += "全局 TUN 会关闭，系统 DNS 与代理恢复原状。"
			}
			if online > 0 {
				line += fmt.Sprintf("当前有 %d 个接入点在线。", online)
			}
			dialogHeader(c, "退出 "+appName+"？", line)
			ui.Text(c, "正在运行的转发和接管会停止，已打开的软件窗口会保留。").
				FontSize(11).TextColor(t.TextMuted).Wrap()
			dialogFooter(c, func() {
				ui.Row(c).Grow(1)
				if ui.Button(c, "取消").FontSize(11).Clicked() {
					a.quitAsk = false
				}
				if ui.Button(c, "确认退出").FontSize(11).Background(t.Danger).
					TextColor(t.AccentText).Clicked() {
					a.quitAsk = false
					a.doQuit()
				}
			})
		})
	})
	if !open {
		a.quitAsk = false
	}
}

// logoutClearsBrowser reports whether discarding a login must also wipe the
// browser data. Only single sign-on keeps its session in a browser; the WeCom
// login lives in the app's own window and its files are not worth touching.
func logoutClearsBrowser(mode model.AuthMode) bool {
	return mode == model.AuthModeSSO
}
