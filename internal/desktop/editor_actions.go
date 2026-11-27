package desktop

import (
	"context"
	"errors"
	"fmt"
	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/ehzyil/connect-hub/internal/store"
	"github.com/ehzyil/connect-hub/internal/vpn"
	"net"
	"strconv"
	"strings"
	"time"
)

// ---- actions ----

func (a *app) openNewEditor() {
	a.editor = editorDraft{
		certificateToken: model.NewID(),
		protocol:         "EasyConnect",
		open:             true,
		address:          "",
		authMode:         string(model.AuthModePassword),
		authModeLabel:    model.AuthModePassword.Label(),
		socksPort:        strconv.Itoa(a.cfg.NextSocksPort()),
		inPool:           true,
		autoConnect:      false,
		monitor:          true,
		monitorEvery:     "300",
		secretStore:      secretStoreLabel(a.cfg.Settings.SecretStore),
	}
}

func (a *app) openEditor(v vpn.View) {
	p := a.cfg.Find(v.ID)
	if p == nil {
		return
	}
	// A LAN relay node has no VPN login form: showing the aTrust/EasyConnect
	// editor would let a save silently rewrite its protocol and drop the share
	// identity it needs to connect. It gets its own read-only panel instead.
	if p.Protocol == model.ProtocolLANRelay {
		a.openRelayPoint(p.ID)
		return
	}
	mode := model.AuthMode(p.AuthMode)
	if mode == model.AuthModeAuto {
		// "自动识别" is gone from the editor: show what the old point has
		// actually been doing, so saving turns it into an explicit mode.
		if a.hasPassword(p.ID) {
			mode = model.AuthModePassword
		} else {
			mode = model.AuthModeWeCom
		}
	}
	a.editor = editorDraft{
		certificateToken:       model.NewID(),
		certificateAddress:     net.JoinHostPort(p.Server, strconv.Itoa(p.Port)),
		certificateAcceptedPin: p.CertificateSHA256,
		open:                   true,
		detailsOpen:            pointNeedsAttention(v),
		editingID:              p.ID,
		protocol:               protocolLabel(p.Protocol),
		healthTarget:           p.HealthTarget,
		remoteDNS:              p.RemoteDNS,
		internalDomains:        strings.Join(p.InternalDomains, ", "),
		certificateSHA256:      p.CertificateSHA256,
		name:                   p.Name,
		address:                model.FormatAccessAddress(p.Server, p.Port),
		username:               p.Username,
		authMode:               string(mode),
		authModeLabel:          mode.Label(),
		domain:                 p.LoginDomain,
		socksPort:              strconv.Itoa(p.SocksPort),
		inPool:                 p.InPool,
		autoConnect:            p.AutoConnect,
		monitor:                p.MonitorEnabled(),
		monitorEvery:           strconv.Itoa(p.MonitorIntervalSeconds()),
		secretStore:            secretStoreLabel(a.cfg.Settings.SecretStore),
		hasPassword:            a.hasPassword(p.ID),
		detected:               nil,
	}
	a.editor.hasTOTP = a.hasTOTP(p.ID)
	if p.RemoteDNS != "" || len(p.InternalDomains) > 0 || p.CertificateSHA256 != "" || p.HealthTarget != "" {
		a.editor.advanced = true
	}
	// A point saved before the mode was a choice gets the mode the server
	// actually offers, picked by detection instead of a "detect yourself"
	// dropdown entry.
	if strings.TrimSpace(p.AuthMode) == "" || model.AuthMode(p.AuthMode) == model.AuthModeAuto {
		a.editor.autoPick = true
	}
	if a.editor.autoPick {
		a.detectEditor()
	}
}

func (a *app) saveEditor() {
	d := &a.editor
	server, port, err := model.ParseAccessAddress(d.address)
	if err != nil {
		d.err = err.Error()
		return
	}
	socksPort, err := parseOptionalPort(d.socksPort)
	if err != nil {
		d.err = "独立 SOCKS5 端口：" + err.Error()
		return
	}
	if strings.TrimSpace(server) == "" {
		d.err = "服务器地址不能为空"
		return
	}
	if err := d.checkCertificateAddress(server, port); err != nil {
		d.err = err.Error()
		return
	}
	mode := string(authModeFromLabel(d.authModeLabel))
	if mode == "" {
		mode = d.authMode
	}
	switch model.AuthMode(mode) {
	case model.AuthModeWeCom, model.AuthModeSSO:
		// Neither needs a username or a stored password: WeCom shows a QR
		// code, single sign-on runs on the portal's own page.
	case model.AuthModeAuto:
		if strings.TrimSpace(d.cred) != "" && strings.TrimSpace(d.username) == "" {
			d.err = "填了密码就要填用户名"
			return
		}
	default:
		if strings.TrimSpace(d.username) == "" {
			d.err = "用户名不能为空"
			return
		}
		if strings.TrimSpace(d.cred) == "" && !d.hasPassword {
			d.err = "请填写密码"
			return
		}
	}
	if !d.inPool && socksPort == 0 {
		d.err = "至少勾选统一入口，或填一个独立 SOCKS5 端口"
		return
	}
	// Switching away from the password mode leaves no one to use a
	// username: drop it so the card does not show an account that is never
	// sent.
	username := strings.TrimSpace(d.username)
	if model.AuthMode(mode) != model.AuthModePassword && model.AuthMode(mode) != model.AuthModeAuto {
		username = ""
	}
	p := model.AccessPoint{
		Protocol:          protocolFromLabel(d.protocol),
		HealthTarget:      strings.TrimSpace(d.healthTarget),
		RemoteDNS:         d.remoteDNS,
		InternalDomains:   strings.FieldsFunc(d.internalDomains, func(r rune) bool { return r == ',' || r == '，' || r == '\n' }),
		CertificateSHA256: d.certificateSHA256,
		ID:                d.editingID,
		Name:              strings.TrimSpace(d.name),
		Server:            server,
		Port:              port,
		Username:          username,
		AuthMode:          mode,
		LoginDomain:       strings.TrimSpace(d.domain),
		SocksPort:         socksPort,
		InPool:            d.inPool,
		AutoConnect:       d.autoConnect,
	}
	monitor := d.monitor
	p.Monitor = &monitor
	if every, err := strconv.Atoi(strings.TrimSpace(d.monitorEvery)); err == nil && every > 0 {
		p.MonitorInterval = every
	} else {
		p.MonitorInterval = 300
	}
	p.Normalize()
	if p.ID == "" {
		p.ID = model.NewID()
	}
	if err := p.Validate(); err != nil {
		d.err = err.Error()
		return
	}
	if socksPort == a.cfg.Settings.AggregatePort {
		d.err = "独立 SOCKS5 端口不能和统一入口端口相同"
		return
	}

	// Secrets first, so that a point is never saved without the creds it
	// needs when the user typed new ones.
	// secretWarning 记录"存进了内存但没存进系统凭据库"：不是保存失败，但也不能静默。
	secretWarning := ""
	if strings.TrimSpace(d.cred) != "" {
		if err := a.store.SetPassword(p.ID, d.cred); err != nil {
			if !errors.Is(err, store.ErrSecretNotPersisted) {
				d.err = "保存密码失败：" + err.Error()
				return
			}
			secretWarning = "系统凭据库不可用：密码只在本次运行有效，重启后需要重新输入"
		}
	}
	if d.clearTOTP {
		if err := a.store.SetTOTP(p.ID, ""); err != nil {
			d.err = "清除 TOTP 失败：" + err.Error()
			return
		}
	} else if strings.TrimSpace(d.totp) != "" {
		if err := a.store.SetTOTP(p.ID, strings.TrimSpace(d.totp)); err != nil {
			if !errors.Is(err, store.ErrSecretNotPersisted) {
				d.err = "保存 TOTP 失败：" + err.Error()
				return
			}
			secretWarning = "系统凭据库不可用：动态口令密钥只在本次运行有效"
		}
	}

	_, err = a.store.Update(func(cfg *model.Config) error {
		for _, other := range cfg.Points {
			if other.ID != p.ID && socksPort > 0 && other.SocksPort == socksPort {
				return fmt.Errorf("SOCKS5 端口 %d 已被「%s」使用", socksPort, other.Name)
			}
		}
		if d.editingID == "" {
			added := cfg.Add(p)
			// Add assigns a free port for callers that do not care; the
			// editor's explicit 0 means "no per-point proxy".
			added.SocksPort = socksPort
			p.ID = added.ID
			return nil
		}
		_, err := cfg.Update(p)
		return err
	})
	if err != nil {
		d.err = err.Error()
		return
	}
	if err := a.saveConfig(); err != nil {
		d.err = "保存配置失败：" + err.Error()
		return
	}
	// The password store is a global setting, chosen here for convenience.
	if newStore := secretStoreFromLabel(d.secretStore); newStore != a.cfg.Settings.SecretStore {
		if _, err := a.store.Update(func(cfg *model.Config) error {
			cfg.Settings.SecretStore = newStore
			return nil
		}); err != nil {
			d.err = "保存密码存储方式失败：" + err.Error()
			return
		}
		if err := a.saveConfig(); err != nil {
			d.err = "保存密码存储方式失败：" + err.Error()
			return
		}
		a.toast = "已保存「" + p.Name + "」，密码存储方式改为「" + d.secretStore + "」，重启后生效"
		d.open = false
		return
	}
	d.open = false
	a.toast = "已保存「" + p.Name + "」"
	if secretWarning != "" {
		a.toast = "已保存「" + p.Name + "」，" + secretWarning
	}
}

// detectEditor asks the server which login methods it offers, for the
// editor's "detect" button. It runs beside the view and updates the draft
// on the main thread.
func (a *app) detectEditor() {
	if a.editor.protocol == "EasyConnect" {
		return
	}
	d := &a.editor
	server, port, err := model.ParseAccessAddress(d.address)
	if err != nil {
		d.detectErr = err.Error()
		d.detected = nil
		return
	}
	d.detecting = true
	d.detectErr = ""
	d.detected = nil
	d.detectGen++
	gen := d.detectGen
	domain := d.domain
	mode := d.authMode
	a.invalidate()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		methods, err := vpn.DetectAuthMethods(ctx, model.AccessPoint{
			Server: server, Port: port, LoginDomain: domain,
		})
		update := func() {
			if d.detectGen != gen || !d.open {
				return
			}
			d.detecting = false
			if err != nil {
				d.detectErr = "检测失败：" + err.Error()
				return
			}
			labels := make([]string, 0, len(methods))
			hasExternal, hasPassword := false, false
			for _, m := range methods {
				labels = append(labels, m.Label())
				switch m.Type {
				case "auth/qywechat", "auth/httpsOauth2", "auth/cas":
					hasExternal = true
				case "auth/psw":
					hasPassword = true
				}
			}
			d.detected = labels
			if len(labels) == 0 {
				d.detectErr = "服务器没有返回可用的认证方式"
				return
			}
			if d.autoPick {
				// 企业微信优先（有扫码就用扫码），其次是单点登录，
				// 最后才是账号密码：这正是服务器给出的顺序所意味的。
				picked := model.AuthModePassword
				switch {
				case hasWeCom(methods):
					picked = model.AuthModeWeCom
				case hasSSO(methods):
					picked = model.AuthModeSSO
				}
				d.authMode = string(picked)
				d.authModeLabel = picked.Label()
				d.autoPick = false
			}
			// 账号密码模式下，服务器只提供密码登录而表单还没填密码时，
			// 直接把下一步说清楚，省得保存后才报错。
			if mode == string(model.AuthModePassword) && !hasExternal && hasPassword && !d.hasPassword && strings.TrimSpace(d.cred) == "" {
				d.detectErr = "服务器只支持账号密码，请填写用户名和密码"
			}
		}
		if a.win != nil {
			a.win.Update(update)
		} else {
			update()
		}
	}()
}

func (a *app) removePoint(id string) {
	// Sharing a point that no longer exists would leave a Blocked share with a
	// dangling identity, so the share is switched off first.
	if a.lanShare != nil {
		if settings := a.lanShare.Settings(); settings.Enabled && settings.PointID == id {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = a.lanShare.Disable(ctx)
			cancel()
		}
	}
	for _, p := range a.cfg.LocalApps {
		if p.PointID == id {
			a.toast = "「" + p.Name + "」仍使用此接入点，请先在本机软件中更换或删除"
			return
		}
	}
	if _, err := a.store.Update(func(cfg *model.Config) error {
		cfg.Remove(id)
		return nil
	}); err != nil {
		a.toast = err.Error()
		return
	}
	if err := a.saveConfig(); err != nil {
		a.toast = "保存配置失败：" + err.Error()
		return
	}
	_ = a.store.DeleteSecrets(id)
	// A relay node also leaves an attribution cache behind. Removing it is part
	// of deleting the node; the deleted point cannot protect anything.
	_ = a.store.DeleteRelayKnown(id)
	// The node is gone, so nothing may keep the unknown-target gate on because of
	// it: the user has no row left to release it from.
	if a.mgr != nil {
		a.mgr.BlockRelayAutoConnect(id, false)
	}
	// Its firewall rule (if the user approved one) belongs to the deleted share.
	a.cancelPendingFirewallOps()
	a.syncLanShareFirewall()
	if a.revealPointID == id {
		a.revealPointID = ""
	}
	a.toast = "已删除接入点"
}

func parsePort(s, what string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("%s必须是 1–65535 的整数", what)
	}
	return port, nil
}

func parseOptionalPort(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	port, err := strconv.Atoi(s)
	if err != nil || port < 0 || port > 65535 {
		return 0, fmt.Errorf("必须是 0–65535 的整数")
	}
	return port, nil
}

// hasWeCom reports whether the server offers the WeCom QR login, which the
// app completes in its own popup.
func hasWeCom(methods []vpn.AuthMethod) bool {
	for _, m := range methods {
		if m.Type == "auth/qywechat" {
			return true
		}
	}
	return false
}

// hasSSO reports whether the server offers a single sign-on that only finishes
// in a real browser.
func hasSSO(methods []vpn.AuthMethod) bool {
	for _, m := range methods {
		switch m.Type {
		case "auth/cas", "auth/httpsOauth2":
			return true
		}
	}
	return false
}
