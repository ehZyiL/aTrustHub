package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ehzyil/connect-hub/internal/model"
)

// autoCapturePhase is the state of the "restore app capture after startup or
// login" helper. It is deliberately separate from CaptureMode: CaptureMode
// records the mode that actually took effect, while this state records whether
// the user asked for an automatic restart and where that attempt stands.
type autoCapturePhase int

const (
	autoCaptureOff autoCapturePhase = iota
	autoCaptureWaiting
	autoCaptureStarting
	autoCaptureRunning
	autoCaptureBackoff
	autoCapturePaused
)

const (
	autoCaptureMaxAttempts = 3
	autoCaptureHelperTTL   = 15 * time.Second
	autoCaptureHelperWait  = 3 * time.Second
	autoCaptureStartGuard  = 5 * time.Second
)

type autoCaptureState struct {
	mu sync.Mutex

	// enabled mirrors Settings.AutoRestoreAppCapture. It is updated by the
	// setter and initialized from the loaded config at startup. The ticker and
	// controller callback read this copy so they never race with saveConfig
	// replacing the app's config value.
	enabled bool
	armed   bool
	phase   autoCapturePhase

	attempts int
	next     time.Time
	lastErr  string
	logKey   string
	waitText string

	lastOnlineSig string
	lastTun       bool
	lastHelper    bool
	helperReady   bool
	helperErr     string
	helperAt      time.Time
	starting      bool
}

// Test seams. Unit tests replace these so they never touch a real helper,
// manager or network stack.
var (
	autoCaptureSupportedFn   = supportsAutoRestoreAppCapture
	autoCaptureHelperReadyFn = autoCaptureHelperReady
	autoCaptureOnlineFn      = func(a *app) autoCaptureTargets { return a.onlineResourceGateways() }
	autoCaptureNowFn         = time.Now
)

func autoCaptureRetryDelay(attempt int) time.Duration {
	if attempt <= 1 {
		return 5 * time.Second
	}
	return 15 * time.Second
}

func (p autoCapturePhase) String() string {
	switch p {
	case autoCaptureWaiting:
		return "waiting"
	case autoCaptureStarting:
		return "starting"
	case autoCaptureRunning:
		return "running"
	case autoCaptureBackoff:
		return "backoff"
	case autoCapturePaused:
		return "paused"
	default:
		return "off"
	}
}

// autoCaptureTargets is the online gateway set the auto-restore state machine
// observes. The signature includes each gateway's generation, so a re-login of
// an already-online gateway is a fresh opportunity even when the count did not
// change (or the logout/login happened between two slow ticks).
type autoCaptureTargets struct {
	count     int
	signature string
}

func (a *app) onlineResourceGateways() autoCaptureTargets {
	if a.mgr == nil {
		return autoCaptureTargets{}
	}
	ids := make([]string, 0, 4)
	for _, gateway := range a.mgr.ResourceGateways() {
		// Strict is checked by resourceCaptureConfigs with a specific error;
		// counting non-strict gateways here lets that error reach the user
		// instead of silently waiting for "another login" forever.
		if gateway.Online && !gateway.Excluded {
			ids = append(ids, fmt.Sprintf("%s#%d", gateway.ID, gateway.Generation))
		}
	}
	sort.Strings(ids)
	return autoCaptureTargets{count: len(ids), signature: strings.Join(ids, "\x00")}
}

func (a *app) autoCaptureTunBlocking() bool {
	if a.tunOn.Load() || a.tunPending.Load() {
		return true
	}
	// On Linux global TUN is not available today, so a stale TunEnabled value
	// from another platform must not block app capture forever.
	return supportsElevatedTUN() && a.configForBackground().Settings.TunEnabled
}

// resetAutoCaptureLocked clears the retry budget and cached helper state for a
// new attempt. The caller must hold autoCapture.mu.
func (a *app) resetAutoCaptureLocked(phase autoCapturePhase) {
	a.autoCapture.armed = true
	a.autoCapture.phase = phase
	a.autoCapture.attempts = 0
	a.autoCapture.next = time.Time{}
	a.autoCapture.lastErr = ""
	a.autoCapture.logKey = ""
	a.autoCapture.waitText = "等待条件满足"
	a.autoCapture.starting = false
	a.autoCapture.helperAt = time.Time{}
	a.autoCapture.helperErr = ""
}

// armAutoCapture starts a fresh automatic attempt. It resets the retry budget
// and any cached helper failure so a login or a user action is observed now.
func (a *app) armAutoCapture(reason string) {
	a.autoCapture.mu.Lock()
	if !a.autoCapture.enabled {
		a.autoCapture.armed = false
		a.autoCapture.phase = autoCaptureOff
		a.autoCapture.mu.Unlock()
		return
	}
	if ok, _ := autoCaptureSupportedFn(); !ok {
		a.autoCapture.armed = false
		a.autoCapture.phase = autoCaptureOff
		a.autoCapture.mu.Unlock()
		return
	}
	a.resetAutoCaptureLocked(autoCaptureWaiting)
	if a.resourceTUNActive() {
		if v := a.resourceTUN.View(); v.Running {
			a.autoCapture.phase = autoCaptureRunning
		} else {
			a.autoCapture.phase = autoCaptureStarting
		}
	}
	a.autoCapture.mu.Unlock()

	if reason == "user" || reason == "retry" {
		a.tunLogf("自动恢复应用接管已开启，等待条件满足")
	}
	a.invalidateCoalesced()
}

// disarmAutoCapture stops future automatic attempts without touching a
// capture that is already running. The persisted setting is the caller's job.
func (a *app) disarmAutoCapture(reason string) {
	a.autoCapture.mu.Lock()
	a.autoCapture.armed = false
	a.autoCapture.phase = autoCaptureOff
	a.autoCapture.attempts = 0
	a.autoCapture.next = time.Time{}
	a.autoCapture.lastErr = ""
	a.autoCapture.logKey = ""
	a.autoCapture.waitText = ""
	a.autoCapture.starting = false
	a.autoCapture.mu.Unlock()
	if reason == "user" {
		a.tunLogf("自动恢复应用接管已关闭")
	}
	a.invalidateCoalesced()
}

func (a *app) retryAutoCapture() {
	a.armAutoCapture("retry")
}

// noticeAppCaptureNotRestored 说清「上次用的是应用接管、这次为什么没接管」。
// 应用接管要拉起提权助手，不能在启动时静默开启，所以默认不自动恢复；但静默
// 地停在「不使用」会让人以为它自己会回来，所以要明确提示一次（不改变任何行为）。
//
// 文案必须跟平台能力一致：Windows 根本没有「自动恢复」这一项（启动助手每次都要
// 过 UAC），指着一个不存在的勾选框只会让人更困惑。
func (a *app) noticeAppCaptureNotRestored(cfg model.Config) {
	if cfg.Settings.CaptureMode != model.CaptureModeApp || cfg.Settings.AutoRestoreAppCapture {
		return
	}
	if a.quitRequested.Load() || a.captureMode() == captureAppCapture {
		return
	}
	if ok, reason := autoCaptureSupportedFn(); !ok {
		a.setToast("上次使用的是「应用接管」，本次没有接管：" + reason + "。需要时在接管方式里重新选一次。")
		a.tunLogf("上次使用的是应用接管，本次不自动接管：本平台不支持自动恢复（%s）", reason)
		return
	}
	a.setToast("上次使用的是「应用接管」，本次未自动接管；勾选「启动 / 登录后自动恢复应用接管」后，下次会自动接管。")
	a.tunLogf("上次使用的是应用接管，但「自动恢复应用接管」未勾选：本次不自动接管（在接管方式下拉里可重新打开）")
}

// rememberAppCaptureIntent 是「用户手动选中应用接管」时的意图记录：下次启动
// 按这个意图自动恢复。只在用户显式选这一档时调用，不在自动恢复流程里调用，
// 所以不会把用户手动取消的勾选又勾回去（取消勾选走 clearAutoRestoreAppCapture）。
//
// 平台不支持自动恢复时一个字也不写：写下去既不会生效，界面上又没有这个开关，
// 用户无法解释也无法撤销这个字段。
func (a *app) rememberAppCaptureIntent() {
	if a.quitRequested.Load() {
		return
	}
	if ok, reason := autoCaptureSupportedFn(); !ok {
		a.tunLogf("本次选择不写进设置：本平台不支持自动恢复应用接管（%s）", reason)
		return
	}
	if err := a.setAutoRestoreAppCapture(true); err != nil {
		a.tunLogf("记住「下次启动自动恢复应用接管」失败：%v", err)
		return
	}
	a.tunLogf("已记下「下次启动自动恢复应用接管」，可在接管设置里取消勾选")
}

func (a *app) autoRestoreEnabled() bool {
	a.autoCapture.mu.Lock()
	defer a.autoCapture.mu.Unlock()
	return a.autoCapture.enabled
}

// clearAutoRestoreAppCapture is the user-facing "stop managing this mode"
// path. It persists the intent as off before stopping the running capture, so
// the next tick and the next launch cannot start it again behind the user's
// back. If persistence fails, the in-session intent is still forced off so a
// disk error cannot resurrect auto restore on the next tick.
func (a *app) clearAutoRestoreAppCapture() {
	a.autoCapture.mu.Lock()
	enabled, armed := a.autoCapture.enabled, a.autoCapture.armed
	a.autoCapture.mu.Unlock()
	if enabled {
		if err := a.setAutoRestoreAppCapture(false); err != nil {
			a.setToast("关闭自动恢复失败：" + err.Error() + "；本次运行已停止自动恢复，重启后请再确认一次")
		}
		return
	}
	if armed {
		a.disarmAutoCapture("user")
	}
}

// setAutoRestoreAppCapture persists the explicit user intent. Turning it off
// only affects future automatic starts; an already running capture is left
// alone until the user switches the capture mode or stops it. Disabling is
// applied to the in-session state before the disk write, so a slow or failing
// save cannot let an in-flight auto start outlive the user's choice.
func (a *app) setAutoRestoreAppCapture(on bool) error {
	if !on {
		a.autoCapture.mu.Lock()
		a.autoCapture.enabled = false
		a.autoCapture.mu.Unlock()
		a.disarmAutoCapture("user")
	}
	if a.store != nil {
		if _, err := a.store.Update(func(cfg *model.Config) error {
			cfg.Settings.AutoRestoreAppCapture = on
			return nil
		}); err != nil {
			return a.failAutoRestoreSetting(on, err)
		}
		if err := a.saveConfig(); err != nil {
			return a.failAutoRestoreSetting(on, err)
		}
	} else {
		a.mutateConfig(func(cfg *model.Config) { cfg.Settings.AutoRestoreAppCapture = on })
	}
	if on {
		a.autoCapture.mu.Lock()
		a.autoCapture.enabled = true
		a.autoCapture.mu.Unlock()
		a.armAutoCapture("user")
	}
	a.invalidate()
	return nil
}

// failAutoRestoreSetting keeps the user's intent authoritative when the config
// write fails. Enabling stays off; disabling was already applied to the
// in-session state and only the persisted value needs a warning.
func (a *app) failAutoRestoreSetting(on bool, err error) error {
	if on {
		// Roll back a store update that could not be saved, so a later
		// unrelated save cannot persist an intent the UI rejected.
		if a.store != nil {
			_, _ = a.store.Update(func(cfg *model.Config) error {
				cfg.Settings.AutoRestoreAppCapture = false
				return nil
			})
		}
		a.mutateConfig(func(cfg *model.Config) { cfg.Settings.AutoRestoreAppCapture = false })
		return err
	}
	a.mutateConfig(func(cfg *model.Config) { cfg.Settings.AutoRestoreAppCapture = false })
	a.autoCapture.mu.Lock()
	a.autoCapture.enabled = false
	a.autoCapture.mu.Unlock()
	a.disarmAutoCapture("")
	return err
}

// cachedAutoCaptureHelper authenticates the Linux helper at most once per TTL.
// A missing or stale helper is a wait condition, not a failed capture attempt,
// so it does not consume the retry budget.
func (a *app) cachedAutoCaptureHelper(now time.Time) (bool, string) {
	a.autoCapture.mu.Lock()
	ready, errText, checked := a.autoCapture.helperReady, a.autoCapture.helperErr, a.autoCapture.helperAt
	a.autoCapture.mu.Unlock()
	if !checked.IsZero() && now.Sub(checked) < autoCaptureHelperTTL {
		return ready, errText
	}

	ctx, cancel := context.WithTimeout(context.Background(), autoCaptureHelperWait)
	err := autoCaptureHelperReadyFn(ctx)
	cancel()
	if err != nil {
		ready, errText = false, err.Error()
	} else {
		ready, errText = true, ""
	}
	a.autoCapture.mu.Lock()
	a.autoCapture.helperReady, a.autoCapture.helperErr, a.autoCapture.helperAt = ready, errText, now
	a.autoCapture.mu.Unlock()
	return ready, errText
}

// maybeAutoRestoreAppCapture is called from the app's slow ticker. It keeps
// trying only while the user's setting is on and arms again when a login or a
// helper recovery creates a new opportunity.
func (a *app) maybeAutoRestoreAppCapture() {
	a.autoCapture.mu.Lock()
	enabled := a.autoCapture.enabled
	a.autoCapture.mu.Unlock()
	if a.quitRequested.Load() || !enabled {
		return
	}
	if ok, _ := autoCaptureSupportedFn(); !ok {
		return
	}

	now := autoCaptureNowFn()
	online := autoCaptureOnlineFn(a)
	tunBlocking := a.autoCaptureTunBlocking()

	// A setting loaded from disk (or a first tick after startup) is enough to
	// arm: manual disarm always clears the persisted setting as well.
	a.autoCapture.mu.Lock()
	if !a.autoCapture.armed {
		a.resetAutoCaptureLocked(autoCaptureWaiting)
		if a.resourceTUNActive() {
			if v := a.resourceTUN.View(); v.Running {
				a.autoCapture.phase = autoCaptureRunning
			} else {
				a.autoCapture.phase = autoCaptureStarting
			}
		}
	}
	// A new login or a TUN handoff is a fresh opportunity: reset the retry
	// budget even if the previous attempts ended in a pause.
	if online.signature != a.autoCapture.lastOnlineSig || (!tunBlocking && a.autoCapture.lastTun) {
		a.autoCapture.attempts = 0
		a.autoCapture.next = time.Time{}
		a.autoCapture.lastErr = ""
		a.autoCapture.logKey = ""
		if a.autoCapture.phase == autoCapturePaused || a.autoCapture.phase == autoCaptureBackoff {
			a.autoCapture.phase = autoCaptureWaiting
		}
	}
	a.autoCapture.lastOnlineSig = online.signature
	a.autoCapture.lastTun = tunBlocking
	next := a.autoCapture.next
	a.autoCapture.mu.Unlock()

	if a.resourceTUNActive() {
		// The controller owns the state while it is running, starting or
		// cleaning up. noteAutoCaptureResult records its result.
		return
	}
	// Starting and Backoff both have a guard time. A controller that never
	// reached Busy must not be started twice in the same tick interval.
	if !next.IsZero() && now.Before(next) {
		return
	}
	if tunBlocking || a.sysProxyOn.Load() {
		a.waitAutoCapture("全局 TUN 或系统代理正在接管")
		return
	}
	if online.count == 0 {
		a.waitAutoCapture("等待网关登录")
		return
	}

	helperReady, helperErr := a.cachedAutoCaptureHelper(now)
	if !helperReady {
		a.autoCapture.mu.Lock()
		a.autoCapture.lastHelper = false
		a.autoCapture.mu.Unlock()
		a.waitAutoCapture("等待网络助手就绪：" + helperErr)
		return
	}

	// Helper readiness is another new opportunity. Reset any earlier failure
	// (for example the helper was installed after a capture start failed).
	a.autoCapture.mu.Lock()
	if !a.autoCapture.enabled || a.quitRequested.Load() || a.tunOn.Load() || a.tunPending.Load() || a.sysProxyOn.Load() {
		a.autoCapture.mu.Unlock()
		return
	}
	if !a.autoCapture.lastHelper {
		a.autoCapture.attempts = 0
		a.autoCapture.next = time.Time{}
		a.autoCapture.lastErr = ""
		a.autoCapture.logKey = ""
		if a.autoCapture.phase == autoCapturePaused || a.autoCapture.phase == autoCaptureBackoff {
			a.autoCapture.phase = autoCaptureWaiting
		}
	}
	a.autoCapture.lastHelper = true
	if a.autoCapture.phase == autoCapturePaused {
		a.autoCapture.mu.Unlock()
		return
	}
	a.autoCapture.phase = autoCaptureStarting
	a.autoCapture.starting = true
	a.autoCapture.next = now.Add(autoCaptureStartGuard)
	a.autoCapture.mu.Unlock()

	a.setupResourceTUN()
	run := a.resourceTUN
	if run == nil {
		a.noteAutoCaptureStartError(errors.New("应用接管控制器未就绪（缺少本机网络管理器）"))
		return
	}
	run.Start()
	// The user may have switched modes or cancelled while the helper check and
	// controller start were in flight. Undo a start that outlived that intent.
	if !a.autoRestoreEnabled() || a.tunOn.Load() || a.tunPending.Load() || a.sysProxyOn.Load() {
		run.Stop()
	}
}

// waitAutoCapture records a non-failure wait. It does not consume attempts and
// only writes a log line when the reason or the surrounding state changes.
func (a *app) waitAutoCapture(reason string) {
	a.autoCapture.mu.Lock()
	if a.autoCapture.phase != autoCapturePaused && a.autoCapture.phase != autoCaptureBackoff {
		a.autoCapture.phase = autoCaptureWaiting
	}
	a.autoCapture.waitText = reason
	key := reason + fmt.Sprintf("|online=%s|helper=%v", a.autoCapture.lastOnlineSig, a.autoCapture.helperReady)
	changed := key != a.autoCapture.logKey
	a.autoCapture.logKey = key
	a.autoCapture.mu.Unlock()
	if changed {
		a.tunLogf("自动恢复应用接管：%s", reason)
		a.invalidateCoalesced()
	}
}

func (a *app) noteAutoCaptureStartError(err error) {
	if err == nil {
		return
	}
	a.autoCapture.mu.Lock()
	if !a.autoCapture.enabled {
		a.autoCapture.mu.Unlock()
		return
	}
	paused, attempts, next := a.recordAutoCaptureFailureLocked(err.Error())
	a.autoCapture.mu.Unlock()
	a.logAutoCaptureFailure(err.Error(), paused, attempts, next)
}

// recordAutoCaptureFailureLocked consumes one retry attempt. The caller must
// hold autoCapture.mu. It is shared by the controller callback and the
// local "controller missing" path so the retry policy cannot drift.
func (a *app) recordAutoCaptureFailureLocked(errText string) (paused bool, attempts int, next time.Time) {
	a.autoCapture.starting = false
	a.autoCapture.attempts++
	a.autoCapture.lastErr = errText
	a.autoCapture.helperAt = time.Time{}
	if a.autoCapture.attempts >= autoCaptureMaxAttempts {
		a.autoCapture.phase = autoCapturePaused
		a.autoCapture.next = time.Time{}
	} else {
		a.autoCapture.phase = autoCaptureBackoff
		a.autoCapture.next = autoCaptureNowFn().Add(autoCaptureRetryDelay(a.autoCapture.attempts))
	}
	return a.autoCapture.phase == autoCapturePaused, a.autoCapture.attempts, a.autoCapture.next
}

func (a *app) logAutoCaptureFailure(errText string, paused bool, attempts int, next time.Time) {
	if paused {
		a.tunLogf("自动恢复应用接管已暂停：%s；修复后点「重试」或重新登录", errText)
	} else {
		a.tunLogf("自动恢复应用接管失败：%s；%s 后重试（第 %d/%d 次）", errText, time.Until(next).Round(time.Second), attempts, autoCaptureMaxAttempts)
	}
	a.invalidateCoalesced()
}

// noteAutoCaptureResult is called by the controller's change callback. It
// returns true when the automatic-restore state owns this result, so the
// caller can avoid rewriting CaptureMode to "off" after an automatic failure.
func (a *app) noteAutoCaptureResult(v resourceTUNStatus) bool {
	a.autoCapture.mu.Lock()
	if !a.autoCapture.enabled {
		a.autoCapture.mu.Unlock()
		return false
	}
	if ok, _ := autoCaptureSupportedFn(); !ok {
		a.autoCapture.mu.Unlock()
		return false
	}
	wasRunning := a.autoCapture.phase == autoCaptureRunning
	wasStarting := a.autoCapture.starting || a.autoCapture.phase == autoCaptureStarting

	switch {
	case v.Running:
		a.autoCapture.phase = autoCaptureRunning
		a.autoCapture.starting = false
		a.autoCapture.attempts = 0
		a.autoCapture.next = time.Time{}
		a.autoCapture.lastErr = ""
		a.autoCapture.waitText = ""
		a.autoCapture.mu.Unlock()
		if !wasRunning && wasStarting {
			a.tunLogf("自动恢复应用接管已就绪：IPv4 TCP + DNS")
		}
		a.invalidateCoalesced()
		return true
	case v.Busy:
		a.autoCapture.phase = autoCaptureStarting
		a.autoCapture.starting = true
		a.autoCapture.mu.Unlock()
		return true
	case v.CleanupPending:
		a.autoCapture.mu.Unlock()
		return true
	case v.Error != "":
		// The controller repeats the same error every couple of seconds. Only
		// a new error consumes an attempt, otherwise the budget would be gone
		// without anything having changed.
		if v.Error == a.autoCapture.lastErr && !wasStarting {
			a.autoCapture.mu.Unlock()
			return true
		}
		paused, attempts, next := a.recordAutoCaptureFailureLocked(v.Error)
		a.autoCapture.mu.Unlock()
		a.logAutoCaptureFailure(v.Error, paused, attempts, next)
		return true
	default:
		a.autoCapture.mu.Unlock()
		return true
	}
}
