package desktop

import (
	"github.com/ehzyil/connect-hub/internal/model"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// 状态机由后台 ticker 驱动（见 startStateTicker），重绘走 redraw.go：
// invalidate 只负责「画」，不再推进任何业务状态。

// maybeResumeTUN re-opens global TUN whenever the remembered switch position
// is "on" and an access point is online again. The position is recorded when
// the switch is flipped, so turning TUN off survives a restart and a new login,
// while turning it on means the next login brings it back.
func (a *app) maybeResumeTUN() {
	if !a.canUseGlobalTUN() {
		return
	}
	if !a.tunWanted.Load() || a.tunOn.Load() || a.tunPending.Load() {
		return
	}
	if time.Now().Before(a.tunResumeAt) {
		return
	}
	if a.tunResumeFails >= 3 {
		return
	}
	id := pickResumePoint(a.configForBackground().Settings.TunPointID, a.mgr.Views())
	if id == "" {
		// 没有在线接入点：把失败计数清零，等下一次登录再试。
		a.tunResumeFails = 0
		return
	}
	a.tunResumeAt = time.Now().Add(30 * time.Second)
	a.tunResumeFails++
	a.tunLogf("按上次的状态恢复全局 TUN（%s，第 %d 次尝试）", id, a.tunResumeFails)
	go a.startGlobalTUN(id)
}

// guardSystemProxy turns the system proxy back off when the unified entry it
// points at is no longer listening. Leaving it on would cut the whole machine
// off, which is worse than losing the VPN.
func (a *app) guardSystemProxy() {
	if a.resourceTUNActive() {
		return
	}
	if !a.sysProxyOn.Load() {
		return
	}
	if a.releaseLostSystemProxy() {
		return
	}
	agg := a.mgr.Aggregate()
	if agg.Running && agg.Addr != "" {
		if conn, err := net.DialTimeout("tcp", agg.Addr, 1500*time.Millisecond); err == nil {
			_ = conn.Close()
			return
		}
	}
	_ = applySystemProxyFn("127.0.0.1:0", false)
	a.sysProxyOn.Store(false)
	a.sysProxySwitch.Store(false)
	// 这是本应用自己关的（入口死了），不是用户放弃接管：入口回来后
	// maybeRestoreCaptureMode 要能把它接回来。用户手动关代理走的是
	// releaseLostSystemProxy，不会走到这里，所以不会被反复抢回去。
	a.captureRestored = false
	a.tunLogf("统一入口已停止监听，已自动关闭系统代理以恢复网络")
	a.toast = "统一入口已停止，已自动关闭系统代理"
	a.invalidate()
}

// maybeRestoreCaptureMode 在启动后按记住的接管方式接管系统代理。默认（也是首次运行）
// 是系统代理：统一入口一开始监听就把它指过去。全局 TUN 有自己的 tunEnabled 恢复路径；
// 应用接管的自动恢复由 auto_capture.go 的独立开关负责，不在这里处理——但这里负责
// 说清楚「上次用的是应用接管、这次为什么不接管」（否则会静默停在「不使用」）。
func (a *app) maybeRestoreCaptureMode() {
	if a.captureRestored {
		return
	}
	// 记着 TUN 意图时让路：TUN 自带 30 秒/3 次的限流重试，别让系统代理抢在它
	// 前面接管。这里也不标记已处理——TUN 因为环境原因放弃后，后续还能再判断。
	cfg := a.configForBackground()
	if cfg.Settings.TunEnabled {
		return
	}
	// 这一档的自动恢复只认「上次生效的就是系统代理」。其它档位在这里让路，
	// 但要先把话说明白：只提示一次，不改变任何接管行为。
	if cfg.Settings.CaptureMode != model.CaptureModeSystem {
		a.noticeAppCaptureNotRestored(cfg)
		a.captureRestored = true
		return
	}
	// macOS 写系统代理要一次管理员授权，每次启动弹密码不可接受；Linux 没有这一档。
	if !supportsAutoSystemProxy() {
		a.captureRestored = true
		return
	}
	// 已经有别的接管方式在负责流量，或者系统代理本来就指着本应用：不用再动。
	if a.tunOn.Load() || a.tunPending.Load() || a.resourceTUNActive() || a.sysProxyOn.Load() {
		a.captureRestored = true
		return
	}
	agg := a.mgr.Aggregate()
	if !cfg.Settings.AggregateEnabled {
		a.captureRestored = true
		a.tunLogf("未自动开启系统代理：统一入口已在设置里关闭")
		return
	}
	if agg.Error != "" {
		a.captureRestored = true
		a.tunLogf("未自动开启系统代理：统一入口不可用（%s）", agg.Error)
		return
	}
	if !agg.Running || agg.Addr == "" {
		return // 入口还没监听，下一轮再看
	}
	// 指到一个没人听的端口会让整台机器断网：先确认它真的在听。
	conn, err := net.DialTimeout("tcp", agg.Addr, 2*time.Second)
	if err != nil {
		return
	}
	_ = conn.Close()
	_, port, err := net.SplitHostPort(agg.Addr)
	if err != nil {
		a.captureRestored = true
		a.tunLogf("未自动开启系统代理：入口地址无法解析（%s）", agg.Addr)
		return
	}
	a.captureRestored = true
	a.enableSystemProxyByDefault(net.JoinHostPort("127.0.0.1", port))
}

// enableSystemProxyByDefault 打开系统代理，但不覆盖别人已经设好的代理：系统代理
// 全机只有一份，抢过来等于替用户改掉了他自己的分流。
//
// 没接管成功时日志和界面提示都写一次：日志在设置页的「状态与日志」里，而用户这
// 一刻看的是首屏，只说在日志里，“登录后没接管”就像是本应用没干活。
func (a *app) enableSystemProxyByDefault(target string) {
	if systemProxyForeignFn(target) {
		// 带上实测值：否则“已被其他软件设置”无法区分是谁占着、占着哪个地址。
		// 再点明它是 Windows 全局设置：删掉应用的数据目录不会影响它，不说清用户会
		// 以为“清空数据 = 恢复默认”，然后觉得提示在胡说。
		detail := systemProxyStateFn(target)
		a.tunLogf("系统代理已被其他软件设置，未自动开启（%s；本应用入口 %s）。"+
			"系统代理是 Windows 全局设置，与数据目录无关；要接管请先关掉占用它的软件，再到下拉里选「系统代理」",
			detail, target)
		a.setToast("系统代理是 Windows 全局设置，现被其他软件占用（" + detail +
			"，本应用入口 " + target + "），本次未自动接管；要接管请先关掉那个软件的系统代理")
		return
	}
	if err := applySystemProxyFn(target, true); err != nil {
		a.tunLogf("自动开启系统代理失败：%v", err)
		a.setToast("自动开启系统代理失败：" + err.Error())
		return
	}
	a.sysProxyOn.Store(true)
	a.tunLogf("网络接管：已按默认设置开启系统代理 %s", target)
	a.invalidateCoalesced()
}

// firstPointID returns the first id of a comma-joined snapshot.
func firstPointID(snapshot string) string {
	for _, id := range strings.Split(snapshot, ",") {
		if id = strings.TrimSpace(id); id != "" {
			return id
		}
	}
	return ""
}

// teardownTUNOnExit stops the helper, makes sure the system DNS is not left
// pointing at 127.0.0.1, and clears the control files.
func (a *app) teardownTUNOnExit() {
	pidPath := filepath.Join(a.dir, "tun.pid")
	_, pidErr := os.Stat(pidPath)
	if !a.tunOn.Load() && pidErr != nil && a.tunPID.Load() <= 0 {
		// 没开过 TUN，但上一次可能被强杀留下了 DNS 劫持，仍然兜底一次。
		return
	}
	// 给 helper 足够时间自己退出：它会在退出前把 DNS 交还系统。
	if !a.shutdownHelper(6 * time.Second) {
		a.tunLogf("退出：helper 未在 6 秒内退出，强制结束后重置 DNS")
	}
	// helper 被强杀时来不及恢复 DNS，这里再兜底一次。
	a.tunOn.Store(false)
	a.tunPID.Store(0)
	for _, name := range []string{"tun.stop", "tun.pid", "tun.reload", "tun.probe", "tun.probe.result"} {
		_ = os.Remove(filepath.Join(a.dir, name))
	}
	a.tunLogf("退出：TUN 已清理，DNS 已交还系统")
}

// disableSystemProxyOnExit turns the system proxy off before quitting, retrying
// once because a failed revert leaves the machine with no usable network.
func (a *app) disableSystemProxyOnExit() {
	if !a.sysProxyOn.Load() {
		return
	}
	if a.releaseLostSystemProxy() {
		return
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := applySystemProxyFn("127.0.0.1:0", false); err == nil {
			a.sysProxyOn.Store(false)
			a.tunLogf("退出：已关闭系统代理")
			return
		} else {
			a.tunLogf("退出：关闭系统代理失败（第 %d 次）：%v", attempt+1, err)
		}
	}
}
