package main

import (
	"fmt"
	"time"
)

// autoCaptureStatusLine is the one-line status shown under the setting.
func (a *app) autoCaptureStatusLine() string {
	a.autoCapture.mu.Lock()
	defer a.autoCapture.mu.Unlock()
	if !a.autoCapture.armed || a.autoCapture.phase == autoCaptureOff {
		return ""
	}
	switch a.autoCapture.phase {
	case autoCaptureWaiting:
		if a.autoCapture.waitText != "" {
			return "自动恢复：" + a.autoCapture.waitText
		}
		return "自动恢复：等待条件满足"
	case autoCaptureStarting:
		return "自动恢复：正在启动…"
	case autoCaptureRunning:
		return "自动恢复：已生效"
	case autoCaptureBackoff:
		wait := time.Until(a.autoCapture.next).Round(time.Second)
		if wait < 0 {
			wait = 0
		}
		return fmt.Sprintf("自动恢复：%s；%s 后重试（第 %d/%d 次）", a.autoCapture.lastErr, wait, a.autoCapture.attempts, autoCaptureMaxAttempts)
	case autoCapturePaused:
		return "自动恢复已暂停：" + a.autoCapture.lastErr
	default:
		return ""
	}
}

func (a *app) autoCapturePaused() bool {
	a.autoCapture.mu.Lock()
	defer a.autoCapture.mu.Unlock()
	return a.autoCapture.armed && a.autoCapture.phase == autoCapturePaused
}
