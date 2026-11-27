package desktop

import (
	"fmt"
	"github.com/ehzyil/connect-hub/internal/model"
	"strconv"
	"strings"
)

func routingLabelStrings() []string {
	out := make([]string, 0, len(model.RoutingLabels))
	for _, entry := range model.RoutingLabels {
		out = append(out, entry.Label)
	}
	return out
}

func routingFromLabel(label string) model.Routing {
	for _, entry := range model.RoutingLabels {
		if entry.Label == label {
			return entry.Value
		}
	}
	return model.RoutingLatency
}

func (a *app) setRouting(r model.Routing) {
	if r == a.cfg.Settings.Routing {
		return
	}
	if _, err := a.store.Update(func(cfg *model.Config) error {
		cfg.Settings.Routing = r
		return nil
	}); err != nil {
		a.toast = err.Error()
		return
	}
	if err := a.saveConfig(); err != nil {
		a.toast = "保存设置失败：" + err.Error()
		return
	}
	a.toast = "分流模式已改为「" + r.Label() + "」"
}

func (a *app) openSettings() {
	s := a.cfg.Settings
	a.settings = settingsDraft{
		open:                  true,
		section:               a.settings.section,
		appearance:            appearanceLabel(a.savedAppearance()),
		theme:                 a.savedTheme(),
		quitOnClose:           s.QuitOnClose,
		autoRestoreAppCapture: s.AutoRestoreAppCapture,
		host:                  s.ListenHost,
		proxyUser:             s.ProxyUsername,
		proxyPass:             s.ProxyPassword,
		port:                  strconv.Itoa(s.AggregatePort),
		interval:              strconv.Itoa(s.HealthIntervalSec),
		routing:               s.Routing.Label(),
		aggregate:             s.AggregateEnabled,
		autoReconnect:         s.AutoReconnect,
		autoCheckUpdate:       s.AutoCheckUpdate,
		secretStore:           secretStoreLabel(s.SecretStore),
		hideDock:              s.HideDock,
		simpleMode:            s.SimpleMode,
	}
}

// openSettingsAt 从顶栏直接进入指定分区：齿轮进上次所在分区，网络状态进网络分区。
func (a *app) openSettingsAt(section int) {
	a.openSettings()
	a.settings.section = section
	if section == settingNetwork {
		// 打开「网络与接管」时把被隐藏的档位和原因写进运行日志：选项不出现，
		// 但用户要能查到为什么没有了。
		a.logHiddenCaptureModes()
	}
	a.invalidate()
}

func (a *app) saveSettings() {
	d := &a.settings
	port, err := parsePort(d.port, "统一入口端口")
	if err != nil {
		d.err = err.Error()
		return
	}
	interval, err := strconv.Atoi(strings.TrimSpace(d.interval))
	if err != nil || interval < 0 {
		d.err = "健康检查间隔必须是不小于 0 的整数"
		return
	}
	host := strings.TrimSpace(d.host)
	if host == "" {
		d.err = "监听地址不能为空"
		return
	}
	// A LAN listener without credentials would be an open relay, so generate one
	// instead of refusing the change; the user can copy it from the same panel.
	if !model.IsLoopbackHost(host) {
		if strings.TrimSpace(d.proxyUser) == "" {
			d.proxyUser = model.ProxyUsernameDefault
		}
		if strings.TrimSpace(d.proxyPass) == "" {
			d.proxyPass = model.NewProxyPassword()
		}
	}
	for _, p := range a.cfg.Points {
		if p.SocksPort == port {
			d.err = fmt.Sprintf("端口 %d 已被「%s」的独立代理使用", port, p.Name)
			return
		}
	}
	_, err = a.store.Update(func(cfg *model.Config) error {
		cfg.Settings.ListenHost = host
		cfg.Settings.ProxyUsername = strings.TrimSpace(d.proxyUser)
		cfg.Settings.ProxyPassword = strings.TrimSpace(d.proxyPass)
		cfg.Settings.AggregatePort = port
		cfg.Settings.HealthIntervalSec = interval
		cfg.Settings.Routing = routingFromLabel(d.routing)
		cfg.Settings.AggregateEnabled = d.aggregate
		cfg.Settings.AutoReconnect = d.autoReconnect
		cfg.Settings.AutoCheckUpdate = d.autoCheckUpdate
		cfg.Settings.HideDock = d.hideDock
		cfg.Settings.Appearance = appearanceFromLabel(d.appearance)
		cfg.Settings.Theme = d.theme
		cfg.Settings.QuitOnClose = d.quitOnClose
		cfg.Settings.SecretStore = secretStoreFromLabel(d.secretStore)
		return cfg.Settings.Validate()
	})
	if err != nil {
		d.err = err.Error()
		return
	}
	if err := a.saveConfig(); err != nil {
		d.err = "保存配置失败：" + err.Error()
		return
	}
	// 实时生效：不关页、不弹提示，输入框里能马上看到结果。
	d.err = ""
}

// applySettingsIfChanged 是「改动即时落盘」的入口：只有草稿真的与
// 已保存的值不同才写一次，避免每帧都碰磁盘。
func (a *app) applySettingsIfChanged() {
	if !a.settingsDirty() {
		return
	}
	a.saveSettings()
}

// settingsDirty 拿草稿和已保存的设置逐项比。
func (a *app) settingsDirty() bool {
	d := &a.settings
	s := a.cfg.Settings
	return strings.TrimSpace(d.host) != s.ListenHost ||
		strings.TrimSpace(d.proxyUser) != s.ProxyUsername ||
		strings.TrimSpace(d.proxyPass) != s.ProxyPassword ||
		strings.TrimSpace(d.port) != strconv.Itoa(s.AggregatePort) ||
		strings.TrimSpace(d.interval) != strconv.Itoa(s.HealthIntervalSec) ||
		appearanceFromLabel(d.appearance) != a.savedAppearance() ||
		d.theme != a.savedTheme() ||
		d.quitOnClose != s.QuitOnClose ||
		routingFromLabel(d.routing) != s.Routing ||
		d.aggregate != s.AggregateEnabled ||
		d.autoReconnect != s.AutoReconnect ||
		d.autoCheckUpdate != s.AutoCheckUpdate ||
		d.hideDock != s.HideDock ||
		secretStoreFromLabel(d.secretStore) != s.SecretStore
}

func secretStoreLabels() []string {
	return []string{"系统钥匙串", "本地文件（明文）"}
}

func secretStoreLabel(v string) string {
	if v == model.SecretStoreKeychain {
		return "系统钥匙串"
	}
	return "本地文件（明文）"
}

func secretStoreFromLabel(label string) string {
	if label == "系统钥匙串" {
		return model.SecretStoreKeychain
	}
	return model.SecretStoreFile
}
