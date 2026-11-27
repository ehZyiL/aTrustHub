//go:build darwin

package desktop

import (
	"errors"
	"strconv"
	"syscall"
	"time"
)

// runProxyWatchdog 是 macOS 版的轻量看门狗：
// 当主程序（GUI）开启系统代理后拉起本守护进程，监听父进程 PID 的退出。
// 无论主程序是正常退出还是被 force quit / kill -9 / 崩溃，一旦父进程消亡，
// 看门狗都会立即苏醒并调用 restoreSystemProxyAfterDeath(dir)。
func runProxyWatchdog(args []string) {
	if len(args) != 2 {
		return
	}
	pid, err := strconv.Atoi(args[0])
	if err != nil || pid <= 0 {
		return
	}
	dir := args[1]

	// 优先使用 Darwin 原生 kqueue 监听父进程退出事件（零 CPU 开销、即时触发）
	if !waitForProcessExitKqueue(pid) {
		// 若 kqueue 不可用或进程已提前消亡，通过轮询兜底
		waitForProcessExitPoll(pid)
	}

	restoreSystemProxyAfterDeath(dir)
}

func waitForProcessExitKqueue(pid int) bool {
	kq, err := syscall.Kqueue()
	if err != nil {
		return false
	}
	defer syscall.Close(kq)

	ev := syscall.Kevent_t{
		Ident:  uint64(pid),
		Filter: syscall.EVFILT_PROC,
		Flags:  syscall.EV_ADD | syscall.EV_ENABLE | syscall.EV_ONESHOT,
		Fflags: syscall.NOTE_EXIT,
	}

	events := make([]syscall.Kevent_t, 1)
	n, err := syscall.Kevent(kq, []syscall.Kevent_t{ev}, events, nil)
	if err != nil {
		// 如果返回 ESRCH，说明父进程在注册监听前就已经退出了
		return errors.Is(err, syscall.ESRCH)
	}
	return n > 0
}

func waitForProcessExitPoll(pid int) {
	for {
		// syscall.Kill(pid, 0) 不发送信号，仅检查进程是否存活
		err := syscall.Kill(pid, 0)
		if err != nil && errors.Is(err, syscall.ESRCH) {
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
}
