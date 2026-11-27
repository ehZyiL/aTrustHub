package desktop

import (
	"github.com/egoist/mygo"
	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/ehzyil/connect-hub/internal/vpn"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// 接管方式的四个档位。系统代理、全局 TUN 与应用接管互斥，所以做成一个下拉。
const (
	captureOff        = "不使用"
	captureSystem     = "系统代理"
	captureGlobalTUN  = "全局 TUN"
	captureAppCapture = "应用接管"
)

// allCaptureModes 是四个档位的固定顺序：下拉、隐藏原因都按它排。
var allCaptureModes = []string{captureOff, captureSystem, captureGlobalTUN, captureAppCapture}

// captureSupported 回答「当前平台和配置能不能提供这一档」。不可用的档位不出现在
// 下拉里，原因写进运行日志。它不看运行时状态：选项列表要稳定，不能因为统一入口
// 还没监听就每帧闪一次。
func (a *app) captureSupported(mode string) (bool, string) {
	switch mode {
	case captureOff:
		return true, ""
	case captureSystem:
		if !supportsSystemProxy() {
			return false, "当前平台不支持系统代理，请手动把软件指向 SOCKS/HTTP 入口"
		}
		return true, ""
	case captureGlobalTUN:
		if !supportsElevatedTUN() {
			return false, "当前平台没有提权 TUN 组件，全局 TUN 依赖 zju-connect-multitun"
		}
		if !a.hasPointWithProtocol(model.ProtocolATrust) {
			if a.hasPointWithProtocol(model.ProtocolEasyConnect) {
				return false, "全局 TUN 只认 aTrust 会话，配置里只有 EasyConnect 接入点；" +
					"EasyConnect 的透明接管请用「应用接管」"
			}
			return false, "还没有 aTrust 接入点，全局 TUN 需要 aTrust 会话"
		}
		return true, ""
	case captureAppCapture:
		if !supportsResourceTUN() {
			return false, "当前平台不支持应用接管，请手动把软件指向 SOCKS/HTTP 入口"
		}
		return true, ""
	}
	return false, "未知的接管方式：" + mode
}

// captureReady 是运行时前置：统一入口要已经在听、要有在线的 aTrust 会话、要至少
// 登录一个网关。它和 captureSupported 一起决定下拉里出现哪些档位。
func (a *app) captureReady(mode string) (bool, string) {
	switch mode {
	case captureSystem:
		if agg := a.mgr.Aggregate(); !agg.Running || agg.Addr == "" {
			return false, "统一入口还没监听，等它启动后再切系统代理"
		}
		return true, ""
	case captureGlobalTUN:
		if a.firstOnlineATrustPoint() == "" {
			return false, "没有在线的 aTrust 接入点，全局 TUN 需要 aTrust 会话"
		}
		return true, ""
	case captureAppCapture:
		if a.resourceTUNActive() {
			return true, ""
		}
		if online, _, _ := a.mgr.Counts(); online == 0 {
			return false, "没有在线接入点，先登录再开应用接管"
		}
		return true, ""
	}
	return true, ""
}

// captureBlocker 回答「这一档现在为什么不能用」，空字符串表示能用。它用于切换前
// 预检：前置不满足时只提示，不动当前正在生效的档位。
func (a *app) captureBlocker(mode string) string {
	if ok, reason := a.captureSupported(mode); !ok {
		return reason
	}
	if ok, reason := a.captureReady(mode); !ok {
		return reason
	}
	return ""
}

// captureModes 是下拉里真正出现的档位：平台/配置做不到的直接隐藏（原因进日志）；
// 做得到但此刻还没条件的仍然列出来，用户点它时给出具体原因。当前生效的那一档
// 一定保留，否则下拉里看不出自己正处在哪一档。
func (a *app) captureModes() []string {
	active := a.captureMode()
	modes := make([]string, 0, len(allCaptureModes))
	for _, mode := range allCaptureModes {
		if mode == active {
			modes = append(modes, mode)
			continue
		}
		if ok, _ := a.captureSupported(mode); ok {
			modes = append(modes, mode)
		}
	}
	return modes
}

// hasPointWithProtocol 看配置里有没有这个协议的接入点，不看是否在线。
func (a *app) hasPointWithProtocol(protocol string) bool {
	// canUseGlobalTUN -> captureSupported -> this runs on the state ticker, so the
	// read has to take the same lock the UI takes when it saves the configuration.
	a.cfgMu.RLock()
	defer a.cfgMu.RUnlock()
	for _, p := range a.cfg.Points {
		if p.Protocol == protocol {
			return true
		}
	}
	return false
}

// captureRefuse 拒绝一次接管切换（或开启）：提示用户，并把原因写进运行日志。
func (a *app) captureRefuse(mode, reason string) {
	a.setToast(reason)
	a.tunLogf("「%s」未生效：%s（当前仍为「%s」）", mode, reason, a.captureMode())
}

// captureModeID 把界面上的档位翻成持久化的 id：设置里存 id，改文案不会让用户
// 记住的接管方式失效。
func captureModeID(mode string) string {
	switch mode {
	case captureSystem:
		return model.CaptureModeSystem
	case captureGlobalTUN:
		return model.CaptureModeTUN
	case captureAppCapture:
		return model.CaptureModeApp
	}
	return model.CaptureModeOff
}

// persistCaptureMode 把「实际生效」的接管方式写进设置，下次启动按它恢复。
// 全局 TUN 另有一套 tunEnabled 开关位置：非 TUN 档位必须把它清掉，否则重启
// 后 TUN 会抢在系统代理前面复活。
func (a *app) persistCaptureMode(mode string) error {
	id := captureModeID(mode)
	apply := func(cfg *model.Config) {
		cfg.Settings.CaptureMode = id
		if mode != captureGlobalTUN {
			cfg.Settings.TunEnabled = false
		}
	}
	if a.store == nil {
		apply(&a.cfg)
		return nil
	}
	if _, err := a.store.Update(func(cfg *model.Config) error { apply(cfg); return nil }); err != nil {
		return err
	}
	return a.saveConfig()
}

// rememberCaptureMode 记住「已经真的生效」的接管方式。只在接管成功启动或已经
// 停下之后调用：存的是结果，不是意图——失败的模式不写进设置，免得下次启动去
// 恢复一个从没跑起来的东西；两边都停了就记成「不使用」。
// 退出过程不记：退出本来就会关代理、停 TUN，记下来会把用户的默认接管清掉。
func (a *app) rememberCaptureMode(mode string) {
	if a.quitRequested.Load() || a.cfg.Settings.CaptureMode == captureModeID(mode) {
		return
	}
	if err := a.persistCaptureMode(mode); err != nil {
		// 记不住不影响当前接管，只记一笔日志。
		a.tunLogf("记住接管方式失败：%v", err)
	}
}

// rememberTunIntent 在用户选中「全局 TUN」时立刻记下意图，不等启动成功：
// TUN 的恢复路径自带限流（30 秒一次、最多 3 次，重建或重登会清零），所以启动
// 失败也值得下次再试。这是唯一一档记「意图」而不是「结果」的：系统代理失败是
// 即时可见的，应用接管在启动时没法自动开。
func (a *app) rememberTunIntent(id string) {
	if a.quitRequested.Load() || id == "" {
		return
	}
	a.persistTunState(true, id)
}

// setToast 是后台 goroutine 的提示入口：界面提示只能在 UI 线程写，
// 没有窗口（单测、退出后）时直接写字段。
func (a *app) setToast(message string) {
	if message == "" {
		return
	}
	if a.win == nil || a.win.IsDestroyed() {
		a.toast = message
		return
	}
	a.win.Update(func() { a.toast = message })
}

// logHiddenCaptureModes 写下哪些档位被隐藏、为什么。只看「平台/配置做不到」这一层：
// 做得到但此刻还没条件的不算隐藏，用户点它时会得到提示。只在原因集合变化时记
// 一次，避免每次打开下拉都刷重复日志。
func (a *app) logHiddenCaptureModes() {
	hidden := make([]string, 0, len(allCaptureModes))
	for _, mode := range allCaptureModes {
		if ok, reason := a.captureSupported(mode); !ok {
			hidden = append(hidden, mode+"："+reason)
		}
	}
	sig := strings.Join(hidden, "；")
	if sig == a.captureHiddenLog {
		return
	}
	a.captureHiddenLog = sig
	if sig == "" {
		a.tunLogf("接管方式：四项都可用")
		return
	}
	a.tunLogf("接管方式里被隐藏：%s", sig)
}

// captureMode 是当前真正生效的接管方式：先看应用接管，再看全局 TUN，最后系统代理。
func (a *app) captureMode() string {
	switch {
	case a.resourceTUNActive():
		return captureAppCapture
	case a.tunOn.Load() || a.tunPending.Load():
		return captureGlobalTUN
	case a.sysProxyOn.Load():
		return captureSystem
	}
	return captureOff
}

// applyCaptureMode 把接管方式切到 mode：先关闭其他两种，再开启所选的。
// 切换是异步的，界面状态每帧从实际状态回读，不依赖本地变量。
func (a *app) applyCaptureMode(mode string) {
	from := a.captureMode()
	if from == mode {
		// 当前生效档位已经相同，但自动恢复可能还在等待/退避：
		// 用户选到非应用接管档位，就等于表示「不要再自动回来」。
		if mode != captureAppCapture {
			a.clearAutoRestoreAppCapture()
		}
		return
	}
	// 先在不碰现有模式的前提下判断目标能不能开：先拆再开会让一次失败的
	// 选择把正在用的接管弄丢。
	if reason := a.captureBlocker(mode); reason != "" {
		a.captureRefuse(mode, reason)
		a.invalidate()
		return
	}
	// 用户主动切到别的档位，就不再希望应用接管自动回来。
	// 注意：目标档位预检失败时不能清，否则当前正在用的应用接管会被
	// 一次失败的切换顺手关掉自动恢复。
	if mode != captureAppCapture {
		a.clearAutoRestoreAppCapture()
	}
	// 先停掉不在目标里的接管方式。这里不能只看 from：自动恢复可能在
	// applyCaptureMode 读到 from 之后、clearAutoRestoreAppCapture 之前启动。
	if mode != captureAppCapture && a.resourceTUN != nil && (from == captureAppCapture || a.resourceTUNActive()) {
		a.resourceTUN.Stop()
	}
	if from == captureGlobalTUN {
		go a.stopTUNSerialized()
	}
	if from == captureSystem && supportsSystemProxy() {
		_ = a.toggleSystemProxy()
	}
	switch mode {
	case captureOff:
		// 用户明确选择「不使用」：这是唯一由界面直接写下的关闭状态。
		a.rememberCaptureMode(captureOff)
	case captureSystem:
		if supportsSystemProxy() && !a.toggleSystemProxy() {
			// 没切过去（例如 TUN 还在停、入口没在听）：不留一个假的目标，
			// 记成「不使用」——下次启动不会去恢复一个从没生效的档位。
			a.rememberCaptureMode(captureOff)
		}
	case captureGlobalTUN:
		// 只能交给 aTrust 点：旧 TUN 组件只读 aTrust 保存的会话。
		if pid := a.firstOnlineATrustPoint(); pid != "" {
			a.tunWanted.Store(true)
			// 选中即记意图：TUN 自己会按限流重试，不依赖这一次能不能起来。
			a.rememberTunIntent(pid)
			go a.startTUNSerialized(pid)
		} else {
			a.captureRefuse(mode, "没有在线的 aTrust 接入点，全局 TUN 需要 aTrust 会话")
		}
	case captureAppCapture:
		// 用户手动选回应用接管时，把自动恢复的退避/暂停也清零，
		// 这样一次手动重试不会被上一轮失败预算挡住。
		if a.autoRestoreEnabled() {
			a.armAutoCapture("manual")
		} else {
			// 用户显式选过这一档，就把「下次启动自动恢复」记下来：重启后
			// 静默回到「不使用」说不通。开关仍可在设置里取消勾选。
			a.rememberAppCaptureIntent()
		}
		a.setupResourceTUN()
		if a.resourceTUN != nil {
			a.resourceTUN.Start()
		}
	}
	a.invalidate()
}

func (a *app) openTUNLog() {
	path := filepath.Join(a.dir, "tun.log")
	if _, err := os.Stat(path); err != nil {
		a.toast = "尚无 TUN 日志；代理请求请查看访问日志"
		return
	}
	if err := mygo.Shell.OpenPath(path); err != nil {
		a.toast = "打开日志失败：" + err.Error()
	}
}

// firstOnlineATrustPoint 返回第一个在线的 aTrust 接入点：旧 TUN 组件只认
// aTrust 保存的会话，选错协议的点它读不到会话文件。
func (a *app) firstOnlineATrustPoint() string {
	for _, v := range a.mgr.Views() {
		if v.State == vpn.StateOnline && v.Protocol == model.ProtocolATrust {
			return v.ID
		}
	}
	return ""
}

// toggleSystemProxy 把系统代理指到统一入口，或清掉，浏览器因此不必手填代理。
// 返回 true 表示已经发起了写入（异步完成）；false 表示压根没动手，调用方据此
// 决定要不要把接管方式降回「不使用」。
func (a *app) toggleSystemProxy() bool {
	if a.resourceTUNActive() {
		a.toast = "请先关闭系统 TUN 再切换系统代理"
		return false
	}
	if a.releaseLostSystemProxy() {
		a.toast = "系统代理已由其他软件修改，已更新开关状态并保留当前配置"
		return false
	}
	if a.tunOn.Load() && !a.sysProxyOn.Load() {
		a.toast = "全局 TUN 已经接管流量，先关掉 TUN 再用系统代理"
		a.sysProxySwitch.Store(a.sysProxyOn.Load())
		return false
	}
	agg := a.mgr.Aggregate()
	if !agg.Running || agg.Addr == "" {
		a.toast = "统一入口还没启动"
		a.sysProxySwitch.Store(a.sysProxyOn.Load())
		return false
	}
	// 先确认代理端口真的在监听：指到一个没人听的端口会让整台机器断网。
	if conn, err := net.DialTimeout("tcp", agg.Addr, 2*time.Second); err != nil {
		a.toast = "统一入口没有在监听，先别开系统代理"
		a.sysProxySwitch.Store(a.sysProxyOn.Load())
		return false
	} else {
		_ = conn.Close()
	}
	port := agg.Addr
	if i := strings.LastIndex(port, ":"); i >= 0 {
		port = port[i+1:]
	}
	target := "127.0.0.1:" + port
	on := !a.sysProxyOn.Load()
	a.toast = "正在修改系统代理，请授权…"
	a.invalidate()
	go func() {
		err := applySystemProxyFn(target, on)
		a.win.Update(func() {
			if err != nil {
				a.toast = "系统代理设置失败：" + err.Error()
				return
			}
			a.sysProxyOn.Store(on)
			if on {
				a.toast = "已把系统代理设为 " + target
			} else {
				a.toast = "已取消系统代理"
			}
		})
		if err != nil {
			return
		}
		// 开启成功之后才记住：记住的是结果，不是意图。
		if on {
			a.rememberCaptureMode(captureSystem)
		}
	}()
	return true
}

// hostInTun reports whether a point is one the running helper serves. The
// snapshot is a comma-joined list of point IDs.
func hostInTun(points, id string) bool {
	for _, p := range strings.Split(points, ",") {
		if strings.TrimSpace(p) == id {
			return true
		}
	}
	return false
}
