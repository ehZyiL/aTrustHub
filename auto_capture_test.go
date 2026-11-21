package main

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/qy/easyconnect/internal/localapps"
	"github.com/qy/easyconnect/internal/model"
)

func autoOnlineTargets(ids ...string) autoCaptureTargets {
	return autoCaptureTargets{count: len(ids), signature: strings.Join(ids, "\x00")}
}

func forceAutoCaptureSupported(t *testing.T) {
	t.Helper()
	prev := autoCaptureSupportedFn
	autoCaptureSupportedFn = func() (bool, string) { return true, "" }
	t.Cleanup(func() { autoCaptureSupportedFn = prev })
}

func stubAutoCaptureReady(t *testing.T, ids ...string) {
	t.Helper()
	prevOnline, prevHelper := autoCaptureOnlineFn, autoCaptureHelperReadyFn
	autoCaptureOnlineFn = func(*app) autoCaptureTargets { return autoOnlineTargets(ids...) }
	autoCaptureHelperReadyFn = func(context.Context) error { return nil }
	t.Cleanup(func() {
		autoCaptureOnlineFn, autoCaptureHelperReadyFn = prevOnline, prevHelper
	})
}

func setAutoRestoreSetting(t *testing.T, a *app, on bool) {
	t.Helper()
	forceAutoCaptureSupported(t)
	if _, err := a.store.Update(func(cfg *model.Config) error {
		cfg.Settings.AutoRestoreAppCapture = on
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	a.cfg = a.store.Config()
	a.autoCapture.mu.Lock()
	a.autoCapture.enabled = a.cfg.Settings.AutoRestoreAppCapture
	a.autoCapture.mu.Unlock()
}

func autoTestController(a *app, start func(context.Context, []localapps.CaptureConfig) (localapps.SystemCapture, error)) *resourceTUNController {
	var c *resourceTUNController
	c = &resourceTUNController{
		configs: func() ([]localapps.CaptureConfig, error) { return nil, nil },
		start:   start,
		suspendProxy: func() (func() error, error) {
			return func() error { return nil }, nil
		},
		change: func() {
			a.noteAutoCaptureResult(c.View())
		},
	}
	a.resourceTUN = c
	return c
}

func waitAutoPhase(t *testing.T, a *app, want autoCapturePhase) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		a.autoCapture.mu.Lock()
		got := a.autoCapture.phase
		a.autoCapture.mu.Unlock()
		if got == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	a.autoCapture.mu.Lock()
	got, reason, attempts := a.autoCapture.phase, a.autoCapture.lastErr, a.autoCapture.attempts
	a.autoCapture.mu.Unlock()
	t.Fatalf("auto phase = %s, want %s (err=%q attempts=%d)", got, want, reason, attempts)
}

func TestAutoRestoreSettingDefaultAndPersistence(t *testing.T) {
	if model.DefaultSettings().AutoRestoreAppCapture {
		t.Fatal("auto restore must default to off")
	}
	s := model.DefaultSettings()
	s.AutoRestoreAppCapture = true
	s.Normalize()
	if !s.AutoRestoreAppCapture {
		t.Fatal("Normalize must preserve an explicit auto-restore choice")
	}
	minimal := model.Settings{AutoRestoreAppCapture: true}
	minimal.Normalize()
	if !minimal.AutoRestoreAppCapture {
		t.Fatal("Normalize must not wipe auto restore from a minimal config")
	}

	a := testApp(t)
	if err := a.setAutoRestoreAppCapture(true); err != nil {
		t.Fatal(err)
	}
	if !a.store.Config().Settings.AutoRestoreAppCapture {
		t.Fatal("enabling auto restore was not persisted")
	}
	if !a.autoCapture.armed {
		t.Fatal("enabling auto restore did not arm the state machine")
	}
	if err := a.setAutoRestoreAppCapture(false); err != nil {
		t.Fatal(err)
	}
	if a.store.Config().Settings.AutoRestoreAppCapture {
		t.Fatal("disabling auto restore was not persisted")
	}
	if a.autoCapture.armed {
		t.Fatal("disabling auto restore did not disarm the state machine")
	}
}

func TestAutoCaptureFailuresKeepOffIntent(t *testing.T) {
	a := testApp(t)
	setAutoRestoreSetting(t, a, true)
	a.cfg.Settings.AutoRestoreAppCapture = true
	a.autoCapture.mu.Lock()
	a.autoCapture.enabled = true
	a.autoCapture.armed = true
	a.autoCapture.phase = autoCaptureWaiting
	a.autoCapture.mu.Unlock()

	if err := a.failAutoRestoreSetting(false, errors.New("disk full")); err == nil {
		t.Fatal("expected the persistence error to be returned")
	}
	if a.cfg.Settings.AutoRestoreAppCapture || a.autoRestoreEnabled() || a.autoCapture.armed {
		t.Fatal("a failed disable must still keep the in-session intent off")
	}

	a.autoCapture.mu.Lock()
	a.autoCapture.armed = false
	a.autoCapture.phase = autoCaptureOff
	a.autoCapture.mu.Unlock()
	if err := a.failAutoRestoreSetting(true, errors.New("disk full")); err == nil {
		t.Fatal("expected the persistence error to be returned")
	}
	if a.autoRestoreEnabled() || a.autoCapture.armed {
		t.Fatal("a failed enable must stay off")
	}
}

func TestAutoCaptureRechecksIntentBeforeStart(t *testing.T) {
	a := testApp(t)
	setAutoRestoreSetting(t, a, true)
	autoCaptureOnlineFn = func(*app) autoCaptureTargets { return autoOnlineTargets("A#1") }
	autoCaptureHelperReadyFn = func(context.Context) error {
		// The user unchecks the box while the helper probe is in flight.
		if err := a.setAutoRestoreAppCapture(false); err != nil {
			t.Fatal(err)
		}
		return nil
	}
	t.Cleanup(func() {
		autoCaptureOnlineFn = func(a *app) autoCaptureTargets { return a.onlineResourceGateways() }
		autoCaptureHelperReadyFn = autoCaptureHelperReady
	})

	var starts atomic.Int32
	c := autoTestController(a, func(context.Context, []localapps.CaptureConfig) (localapps.SystemCapture, error) {
		starts.Add(1)
		return &controllerRuntime{done: make(chan struct{})}, nil
	})
	t.Cleanup(func() { _ = c.Close() })

	a.maybeAutoRestoreAppCapture()
	if starts.Load() != 0 {
		t.Fatal("capture started after the user unchecked auto restore")
	}
	if a.autoRestoreEnabled() || a.autoCapture.armed {
		t.Fatal("unchecking during the helper probe did not disarm")
	}
}

func TestAutoCaptureLazyArmKeepsRunningPhase(t *testing.T) {
	a := testApp(t)
	setAutoRestoreSetting(t, a, true)
	// Simulate a controller that was manually started before the first tick.
	r := &controllerRuntime{done: make(chan struct{})}
	a.resourceTUN = &resourceTUNController{current: r, status: resourceTUNStatus{Running: true}}
	t.Cleanup(func() { _ = a.resourceTUN.Close() })
	stubAutoCaptureReady(t, "A#1")

	a.maybeAutoRestoreAppCapture()
	waitAutoPhase(t, a, autoCaptureRunning)
}

func TestAutoCaptureHelperRecoveryRearmsPaused(t *testing.T) {
	a := testApp(t)
	setAutoRestoreSetting(t, a, true)
	autoCaptureOnlineFn = func(*app) autoCaptureTargets { return autoOnlineTargets("A#1") }
	helperReady := true
	autoCaptureHelperReadyFn = func(context.Context) error {
		if helperReady {
			return nil
		}
		return errors.New("helper down")
	}
	now := time.Now()
	autoCaptureNowFn = func() time.Time { return now }
	t.Cleanup(func() {
		autoCaptureOnlineFn = func(a *app) autoCaptureTargets { return a.onlineResourceGateways() }
		autoCaptureHelperReadyFn = autoCaptureHelperReady
		autoCaptureNowFn = time.Now
	})

	var starts atomic.Int32
	c := autoTestController(a, func(context.Context, []localapps.CaptureConfig) (localapps.SystemCapture, error) {
		starts.Add(1)
		return nil, errors.New("route conflict")
	})
	t.Cleanup(func() { _ = c.Close() })

	// Exhaust the retry budget with a working helper.
	for i := 0; i < autoCaptureMaxAttempts; i++ {
		a.maybeAutoRestoreAppCapture()
		if i == 0 {
			waitAutoPhase(t, a, autoCaptureBackoff)
		} else if i == 1 {
			now = now.Add(5 * time.Second)
			a.maybeAutoRestoreAppCapture()
			waitAutoPhase(t, a, autoCaptureBackoff)
		} else {
			now = now.Add(15 * time.Second)
			a.maybeAutoRestoreAppCapture()
			waitAutoPhase(t, a, autoCapturePaused)
		}
	}
	if starts.Load() != 3 {
		t.Fatalf("starts = %d, want 3", starts.Load())
	}

	// The helper drops while paused. It must not consume attempts, and its
	// recovery must reset the pause and try again.
	helperReady = false
	now = now.Add(16 * time.Second)
	a.maybeAutoRestoreAppCapture()
	a.autoCapture.mu.Lock()
	phase := a.autoCapture.phase
	lastHelper := a.autoCapture.lastHelper
	a.autoCapture.mu.Unlock()
	if phase != autoCapturePaused || lastHelper {
		t.Fatalf("helper outage changed pause state: phase=%s lastHelper=%v", phase, lastHelper)
	}

	helperReady = true
	now = now.Add(16 * time.Second)
	a.maybeAutoRestoreAppCapture()
	waitAutoPhase(t, a, autoCaptureBackoff)
	if starts.Load() != 4 {
		t.Fatalf("helper recovery did not rearm: starts = %d", starts.Load())
	}
}

func TestAutoCaptureStartsWhenConditionsAreReady(t *testing.T) {
	a := testApp(t)
	setAutoRestoreSetting(t, a, true)
	stubAutoCaptureReady(t, "A#1")

	var starts atomic.Int32
	r := &controllerRuntime{done: make(chan struct{})}
	c := autoTestController(a, func(context.Context, []localapps.CaptureConfig) (localapps.SystemCapture, error) {
		starts.Add(1)
		return r, nil
	})
	t.Cleanup(func() { _ = c.Close() })

	a.maybeAutoRestoreAppCapture()
	waitController(t, c, func(s resourceTUNStatus) bool { return s.Running })
	waitAutoPhase(t, a, autoCaptureRunning)
	if !strings.Contains(tailLog(a.bus.Tail(30)), "自动恢复应用接管已就绪") {
		t.Fatalf("success was not logged: %s", tailLog(a.bus.Tail(30)))
	}
	if got := a.autoCaptureStatusLine(); !strings.Contains(got, "已生效") {
		t.Fatalf("status = %q", got)
	}
	// Once the controller is active, the ticker must not start a second one.
	a.maybeAutoRestoreAppCapture()
	if starts.Load() != 1 {
		t.Fatalf("capture was started twice: %d", starts.Load())
	}
}

func TestAutoCaptureWaitsForOnlineGatewayThenStarts(t *testing.T) {
	a := testApp(t)
	setAutoRestoreSetting(t, a, true)
	online := autoOnlineTargets()
	autoCaptureOnlineFn = func(*app) autoCaptureTargets { return online }
	autoCaptureHelperReadyFn = func(context.Context) error { return nil }
	t.Cleanup(func() {
		autoCaptureOnlineFn = func(a *app) autoCaptureTargets { return a.onlineResourceGateways() }
		autoCaptureHelperReadyFn = autoCaptureHelperReady
	})

	var starts atomic.Int32
	r := &controllerRuntime{done: make(chan struct{})}
	c := autoTestController(a, func(context.Context, []localapps.CaptureConfig) (localapps.SystemCapture, error) {
		starts.Add(1)
		return r, nil
	})
	t.Cleanup(func() { _ = c.Close() })

	a.maybeAutoRestoreAppCapture()
	if starts.Load() != 0 {
		t.Fatal("capture started without an online resource gateway")
	}
	if got := a.autoCaptureStatusLine(); !strings.Contains(got, "等待网关登录") {
		t.Fatalf("status = %q", got)
	}

	online = autoOnlineTargets("A#1")
	a.maybeAutoRestoreAppCapture()
	waitController(t, c, func(s resourceTUNStatus) bool { return s.Running })
	waitAutoPhase(t, a, autoCaptureRunning)
	if starts.Load() != 1 {
		t.Fatalf("starts = %d, want 1", starts.Load())
	}
}

func TestAutoCaptureWaitsForHelperThenRecovers(t *testing.T) {
	a := testApp(t)
	setAutoRestoreSetting(t, a, true)
	autoCaptureOnlineFn = func(*app) autoCaptureTargets { return autoOnlineTargets("A#1") }
	helperReady := false
	autoCaptureHelperReadyFn = func(context.Context) error {
		if helperReady {
			return nil
		}
		return errors.New("helper not running")
	}
	now := time.Now()
	autoCaptureNowFn = func() time.Time { return now }
	t.Cleanup(func() {
		autoCaptureOnlineFn = func(a *app) autoCaptureTargets { return a.onlineResourceGateways() }
		autoCaptureHelperReadyFn = autoCaptureHelperReady
		autoCaptureNowFn = time.Now
	})

	var starts atomic.Int32
	r := &controllerRuntime{done: make(chan struct{})}
	c := autoTestController(a, func(context.Context, []localapps.CaptureConfig) (localapps.SystemCapture, error) {
		starts.Add(1)
		return r, nil
	})
	t.Cleanup(func() { _ = c.Close() })

	a.maybeAutoRestoreAppCapture()
	if starts.Load() != 0 {
		t.Fatal("capture started without a ready helper")
	}
	if got := a.autoCaptureStatusLine(); !strings.Contains(got, "等待网络助手就绪") {
		t.Fatalf("status = %q", got)
	}

	helperReady = true
	now = now.Add(16 * time.Second) // expire the helper probe cache
	a.maybeAutoRestoreAppCapture()
	waitController(t, c, func(s resourceTUNStatus) bool { return s.Running })
	waitAutoPhase(t, a, autoCaptureRunning)
	if starts.Load() != 1 {
		t.Fatalf("starts = %d, want 1", starts.Load())
	}
}

func TestAutoCaptureBacksOffThenPausesAndRearmsOnLogin(t *testing.T) {
	a := testApp(t)
	setAutoRestoreSetting(t, a, true)
	online := autoOnlineTargets("A#1")
	autoCaptureOnlineFn = func(*app) autoCaptureTargets { return online }
	autoCaptureHelperReadyFn = func(context.Context) error { return nil }
	now := time.Now()
	autoCaptureNowFn = func() time.Time { return now }
	t.Cleanup(func() {
		autoCaptureOnlineFn = func(a *app) autoCaptureTargets { return a.onlineResourceGateways() }
		autoCaptureHelperReadyFn = autoCaptureHelperReady
		autoCaptureNowFn = time.Now
	})

	var starts atomic.Int32
	c := autoTestController(a, func(context.Context, []localapps.CaptureConfig) (localapps.SystemCapture, error) {
		starts.Add(1)
		return nil, errors.New("route conflict")
	})
	t.Cleanup(func() { _ = c.Close() })

	a.maybeAutoRestoreAppCapture()
	waitAutoPhase(t, a, autoCaptureBackoff)
	if starts.Load() != 1 {
		t.Fatalf("starts = %d, want 1", starts.Load())
	}

	a.maybeAutoRestoreAppCapture()
	if starts.Load() != 1 {
		t.Fatalf("retried before the backoff expired: starts = %d", starts.Load())
	}

	now = now.Add(5 * time.Second)
	a.maybeAutoRestoreAppCapture()
	waitAutoPhase(t, a, autoCaptureBackoff)
	if starts.Load() != 2 {
		t.Fatalf("starts = %d, want 2", starts.Load())
	}

	now = now.Add(15 * time.Second)
	a.maybeAutoRestoreAppCapture()
	waitAutoPhase(t, a, autoCapturePaused)
	if starts.Load() != 3 {
		t.Fatalf("starts = %d, want 3", starts.Load())
	}
	if !strings.Contains(tailLog(a.bus.Tail(30)), "自动恢复应用接管已暂停") {
		t.Fatalf("pause was not logged: %s", tailLog(a.bus.Tail(30)))
	}

	// The retry button is a fresh opportunity even after the budget ran out.
	a.retryAutoCapture()
	a.maybeAutoRestoreAppCapture()
	waitAutoPhase(t, a, autoCaptureBackoff)
	if starts.Load() != 4 {
		t.Fatalf("retry did not rearm the attempt: starts = %d", starts.Load())
	}

	// A fresh login of the same gateway changes its generation even though the
	// online count stays at one; it must still rearm.
	online = autoOnlineTargets("A#2")
	a.maybeAutoRestoreAppCapture()
	waitAutoPhase(t, a, autoCaptureBackoff)
	if starts.Load() != 5 {
		t.Fatalf("login did not rearm the attempt: starts = %d", starts.Load())
	}
}

func TestAutoCaptureManualOffDisablesSettingAndStops(t *testing.T) {
	a := testApp(t)
	setAutoRestoreSetting(t, a, true)
	stubAutoCaptureReady(t, "A#1")

	r := &controllerRuntime{done: make(chan struct{})}
	c := autoTestController(a, func(context.Context, []localapps.CaptureConfig) (localapps.SystemCapture, error) {
		return r, nil
	})
	t.Cleanup(func() { _ = c.Close() })

	a.maybeAutoRestoreAppCapture()
	waitController(t, c, func(s resourceTUNStatus) bool { return s.Running })

	a.applyCaptureMode(captureOff)
	waitController(t, c, func(s resourceTUNStatus) bool { return !s.Running && !s.Busy })
	if a.store.Config().Settings.AutoRestoreAppCapture {
		t.Fatal("manual switch to off did not clear the persisted auto-restore setting")
	}
	if a.autoCapture.armed {
		t.Fatal("manual switch to off did not disarm auto restore")
	}
}

func TestUncheckingAutoRestoreDoesNotStopRunningCapture(t *testing.T) {
	a := testApp(t)
	setAutoRestoreSetting(t, a, true)
	stubAutoCaptureReady(t, "A#1")

	r := &controllerRuntime{done: make(chan struct{})}
	c := autoTestController(a, func(context.Context, []localapps.CaptureConfig) (localapps.SystemCapture, error) {
		return r, nil
	})
	t.Cleanup(func() { _ = c.Close() })

	a.maybeAutoRestoreAppCapture()
	waitController(t, c, func(s resourceTUNStatus) bool { return s.Running })

	if err := a.setAutoRestoreAppCapture(false); err != nil {
		t.Fatal(err)
	}
	if !c.View().Running {
		t.Fatal("unchecking auto restore must not stop an already running capture")
	}
	if a.autoCapture.armed {
		t.Fatal("unchecking auto restore must disarm future attempts")
	}
}

func TestAutoCaptureDoesNotStartWhileTunIsActive(t *testing.T) {
	a := testApp(t)
	setAutoRestoreSetting(t, a, true)
	a.tunOn = true
	autoCaptureOnlineFn = func(*app) autoCaptureTargets { return autoOnlineTargets("A#1") }
	autoCaptureHelperReadyFn = func(context.Context) error { return nil }
	t.Cleanup(func() {
		a.tunOn = false
		autoCaptureOnlineFn = func(a *app) autoCaptureTargets { return a.onlineResourceGateways() }
		autoCaptureHelperReadyFn = autoCaptureHelperReady
	})

	var starts atomic.Int32
	c := autoTestController(a, func(context.Context, []localapps.CaptureConfig) (localapps.SystemCapture, error) {
		starts.Add(1)
		return &controllerRuntime{done: make(chan struct{})}, nil
	})
	t.Cleanup(func() { _ = c.Close() })

	a.maybeAutoRestoreAppCapture()
	if starts.Load() != 0 {
		t.Fatal("capture started while global TUN was active")
	}
	if got := a.autoCaptureStatusLine(); !strings.Contains(got, "全局 TUN") {
		t.Fatalf("status = %q", got)
	}
}

func TestAutoCaptureOwnsFailureResult(t *testing.T) {
	a := testApp(t)
	setAutoRestoreSetting(t, a, true)
	a.autoCapture.mu.Lock()
	a.autoCapture.armed = true
	a.autoCapture.phase = autoCaptureStarting
	a.autoCapture.starting = true
	a.autoCapture.mu.Unlock()
	if !a.noteAutoCaptureResult(resourceTUNStatus{Error: "route conflict"}) {
		t.Fatal("an enabled auto restore must own the failure result")
	}
	waitAutoPhase(t, a, autoCaptureBackoff)
	a.autoCapture.mu.Lock()
	attempts := a.autoCapture.attempts
	a.autoCapture.mu.Unlock()
	// The controller repeats the same error; it must not consume the budget.
	if !a.noteAutoCaptureResult(resourceTUNStatus{Error: "route conflict"}) {
		t.Fatal("repeated failure should stay owned by auto restore")
	}
	a.autoCapture.mu.Lock()
	repeated := a.autoCapture.attempts
	a.autoCapture.mu.Unlock()
	if repeated != attempts {
		t.Fatalf("repeated error consumed an attempt: %d -> %d", attempts, repeated)
	}

	if err := a.setAutoRestoreAppCapture(false); err != nil {
		t.Fatal(err)
	}
	if a.noteAutoCaptureResult(resourceTUNStatus{Error: "route conflict"}) {
		t.Fatal("a disabled auto restore must leave manual failure handling alone")
	}
}

func TestAutoCaptureRearmsAfterTunStops(t *testing.T) {
	a := testApp(t)
	setAutoRestoreSetting(t, a, true)
	a.tunOn = true
	autoCaptureOnlineFn = func(*app) autoCaptureTargets { return autoOnlineTargets("A#1") }
	autoCaptureHelperReadyFn = func(context.Context) error { return nil }
	t.Cleanup(func() {
		a.tunOn = false
		autoCaptureOnlineFn = func(a *app) autoCaptureTargets { return a.onlineResourceGateways() }
		autoCaptureHelperReadyFn = autoCaptureHelperReady
	})

	var starts atomic.Int32
	r := &controllerRuntime{done: make(chan struct{})}
	c := autoTestController(a, func(context.Context, []localapps.CaptureConfig) (localapps.SystemCapture, error) {
		starts.Add(1)
		return r, nil
	})
	t.Cleanup(func() { _ = c.Close() })

	a.maybeAutoRestoreAppCapture()
	if starts.Load() != 0 {
		t.Fatal("capture started while global TUN was active")
	}
	a.tunOn = false
	a.maybeAutoRestoreAppCapture()
	waitController(t, c, func(s resourceTUNStatus) bool { return s.Running })
	waitAutoPhase(t, a, autoCaptureRunning)
	if starts.Load() != 1 {
		t.Fatalf("TUN stop did not rearm capture: starts = %d", starts.Load())
	}
}

func TestAutoCaptureUserCancelDisablesAndStops(t *testing.T) {
	a := testApp(t)
	setAutoRestoreSetting(t, a, true)
	stubAutoCaptureReady(t, "A#1")

	r := &controllerRuntime{done: make(chan struct{})}
	c := autoTestController(a, func(context.Context, []localapps.CaptureConfig) (localapps.SystemCapture, error) {
		return r, nil
	})
	t.Cleanup(func() { _ = c.Close() })

	a.maybeAutoRestoreAppCapture()
	waitController(t, c, func(s resourceTUNStatus) bool { return s.Running })
	a.stopAppCaptureByUser()
	waitController(t, c, func(s resourceTUNStatus) bool { return !s.Running && !s.Busy })
	if a.store.Config().Settings.AutoRestoreAppCapture {
		t.Fatal("cancel did not clear the persisted auto-restore setting")
	}
	if a.autoRestoreEnabled() || a.autoCapture.armed {
		t.Fatal("cancel did not disarm auto restore")
	}
	if got := a.store.Config().Settings.CaptureMode; got != model.CaptureModeOff {
		t.Fatalf("cancel should remember off, got %q", got)
	}
}

func TestAutoCaptureUnsupportedPlatformStaysOff(t *testing.T) {
	a := testApp(t)
	setAutoRestoreSetting(t, a, true)
	autoCaptureSupportedFn = func() (bool, string) { return false, "not supported" }
	t.Cleanup(func() { autoCaptureSupportedFn = supportsAutoRestoreAppCapture })

	var starts atomic.Int32
	c := autoTestController(a, func(context.Context, []localapps.CaptureConfig) (localapps.SystemCapture, error) {
		starts.Add(1)
		return &controllerRuntime{done: make(chan struct{})}, nil
	})
	t.Cleanup(func() { _ = c.Close() })

	a.maybeAutoRestoreAppCapture()
	if starts.Load() != 0 {
		t.Fatal("capture started on an unsupported platform")
	}
}

func TestSettingsPageShowsPausedAutoRestoreAndRetry(t *testing.T) {
	a := testApp(t)
	forceAutoCaptureSupported(t)
	a.cfg.Settings.AutoRestoreAppCapture = true
	a.autoCapture.mu.Lock()
	a.autoCapture.enabled = true
	a.autoCapture.armed = true
	a.autoCapture.phase = autoCapturePaused
	a.autoCapture.attempts = autoCaptureMaxAttempts
	a.autoCapture.lastErr = "route conflict"
	a.autoCapture.mu.Unlock()
	a.openSettingsAt(settingNetwork)

	tt := ui.NewTester(a.view, 1120, 800)
	tt.Frame()
	texts := strings.Join(tt.Texts(), "|")
	if !strings.Contains(texts, "自动恢复已暂停") || !strings.Contains(texts, "route conflict") {
		t.Fatalf("paused status missing: %s", texts)
	}
	if err := tt.Click("重试"); err != nil {
		t.Fatalf("click retry: %v", err)
	}
	tt.Frame()
	a.autoCapture.mu.Lock()
	phase, attempts := a.autoCapture.phase, a.autoCapture.attempts
	a.autoCapture.mu.Unlock()
	if phase != autoCaptureWaiting || attempts != 0 {
		t.Fatalf("retry did not rearm: phase=%s attempts=%d", phase, attempts)
	}
}

func TestSettingsPageExplainsUnsupportedAutoRestore(t *testing.T) {
	a := testApp(t)
	autoCaptureSupportedFn = func() (bool, string) { return false, "需要管理员授权" }
	t.Cleanup(func() { autoCaptureSupportedFn = supportsAutoRestoreAppCapture })
	a.openSettingsAt(settingNetwork)
	tt := ui.NewTester(a.view, 1120, 800)
	tt.Frame()
	texts := strings.Join(tt.Texts(), "|")
	if !strings.Contains(texts, "自动恢复不可用：需要管理员授权") {
		t.Fatalf("unsupported reason missing: %s", texts)
	}
	if strings.Contains(texts, "启动 / 登录后自动恢复应用接管") {
		t.Fatalf("unsupported platform must not show the checkbox: %s", texts)
	}
}

func TestSettingsPageShowsAutoRestoreCheckbox(t *testing.T) {
	a := testApp(t)
	forceAutoCaptureSupported(t)
	a.openSettingsAt(settingNetwork)
	tt := ui.NewTester(a.view, 1120, 800)
	tt.Frame()
	texts := strings.Join(tt.Texts(), "|")
	for _, want := range []string{"启动 / 登录后自动恢复应用接管", "网络助手就绪"} {
		if !strings.Contains(texts, want) {
			t.Fatalf("settings page lacks %q: %s", want, texts)
		}
	}
	if err := tt.Click("启动 / 登录后自动恢复应用接管"); err != nil {
		t.Fatalf("click checkbox: %v", err)
	}
	tt.Frame()
	if !a.store.Config().Settings.AutoRestoreAppCapture {
		t.Fatal("clicking the checkbox did not persist auto restore")
	}
	if !a.autoCapture.armed {
		t.Fatal("clicking the checkbox did not arm auto restore")
	}
}
