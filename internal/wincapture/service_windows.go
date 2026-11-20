package wincapture

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func RunHelper(ctx context.Context, id string, parentIdentity Identity) error {
	f, parent, err := connectDesktop(ctx, id, parentIdentity)
	if err != nil {
		return err
	}
	defer f.Close()
	defer windows.CloseHandle(parent)
	life, cancel := context.WithCancel(ctx)
	defer cancel()
	guard, err := startWatchdog(life, id)
	if err != nil {
		return err
	}
	defer guard.Close()
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-life.Done():
				return
			case <-ticker.C:
				for _, h := range []windows.Handle{parent, guard.handle} {
					state, err := windows.WaitForSingleObject(h, 0)
					if err != nil || state != uint32(windows.WAIT_TIMEOUT) {
						cancel()
						f.Close()
						return
					}
				}
			}
		}
	}()
	defer func() { cancel(); <-watchDone }()
	stop := context.AfterFunc(life, func() { f.Close() })
	defer stop()
	reader := bufio.NewReaderSize(f, maxFrame)
	var backend *engine
	defer func() {
		if backend != nil {
			_ = backend.drain()
			_ = backend.Close()
		}
	}()
	for {
		if err = f.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
			return err
		}
		var req frame
		if err = readFrame(reader, &req); err != nil {
			return err
		}
		reply := frame{Type: "ok"}
		var actionErr error
		switch req.Type {
		case "configure":
			if backend != nil || req.Config == nil {
				actionErr = errors.New("网络助手已配置或配置缺失")
				break
			}
			if actionErr = RecoverOrphanedDNS(life); actionErr != nil {
				break
			}
			backend, actionErr = newEngine(context.Background(), id, parent, *req.Config)
			if actionErr == nil {
				reply.Prefix = backend.aliases.String()
			}
		case "ping":
			if backend != nil {
				actionErr = backend.checkNetwork()
			}
		case "close":
			if backend != nil {
				actionErr = backend.beginDrain()
			}
		case "attach", "detach", "publish":
			if backend == nil {
				actionErr = errors.New("网络助手尚未配置")
				break
			}
			switch req.Type {
			case "attach":
				actionErr = backend.attach(req.Attach)
			case "detach":
				actionErr = backend.detach(req.ID)
			case "publish":
				actionErr = backend.publish(req.Aliases)
			}
		default:
			actionErr = errors.New("未知网络助手请求")
		}
		if actionErr != nil {
			reply.Type, reply.Error = "error", actionErr.Error()
		}
		if err = f.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return err
		}
		if err = writeFrame(f, reply); err != nil {
			return err
		}
		if req.Type == "close" {
			return actionErr
		}
	}
}

type watchdog struct{ handle windows.Handle }

func (w *watchdog) Close() { _ = windows.CloseHandle(w.handle) }

func startWatchdog(ctx context.Context, id string) (*watchdog, error) {
	name, _ := windows.UTF16PtrFromString(`Local\EasyConnectHub-Recovery-` + id)
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;SY)(A;;GA;;;BA)")
	if err != nil {
		return nil, err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	event, err := windows.CreateEvent(&sa, 1, 0, name)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(event)
	self, err := processIdentity(windows.CurrentProcess(), uint32(os.Getpid()))
	if err != nil {
		return nil, err
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(exe, "--watchdog", id, "--parent", strconv.FormatUint(uint64(self.PID), 10), "--created", strconv.FormatUint(self.Created, 10))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err = cmd.Start(); err != nil {
		return nil, err
	}
	go func() { _ = cmd.Wait() }()
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(cmd.Process.Pid))
	if err != nil {
		return nil, err
	}
	ready := false
	defer func() {
		if !ready {
			windows.CloseHandle(handle)
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		state, err := windows.WaitForSingleObject(event, 50)
		if err != nil {
			return nil, err
		}
		if state == windows.WAIT_OBJECT_0 {
			ready = true
			return &watchdog{handle}, nil
		}
		state, _ = windows.WaitForSingleObject(handle, 0)
		if state != uint32(windows.WAIT_TIMEOUT) {
			return nil, errors.New("网络恢复助手提前退出")
		}
	}
	return nil, errors.New("网络恢复助手未就绪")
}

// The elevated watchdog is started and acknowledged before any DNS policy is
// installed. It removes only this random session's NRPT rules if the engine
// crashes. The engine also watches the watchdog, so losing either stops capture.
func RunWatchdog(ctx context.Context, id string, expected Identity) error {
	if !validID(id) || expected.PID == 0 || !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("恢复助手参数或权限无效")
	}
	parent, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, expected.PID)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(parent)
	actual, err := processIdentity(parent, expected.PID)
	if err != nil || actual != expected {
		return errors.New("恢复助手父进程身份已改变")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if err = verifyExecutable(parent, exe); err != nil {
		return err
	}
	name, _ := windows.UTF16PtrFromString(`Local\EasyConnectHub-Recovery-` + id)
	event, err := windows.OpenEvent(windows.EVENT_MODIFY_STATE, false, name)
	if err != nil {
		return err
	}
	err = windows.SetEvent(event)
	windows.CloseHandle(event)
	if err != nil {
		return err
	}
	for {
		state, err := windows.WaitForSingleObject(parent, 250)
		if err != nil {
			return err
		}
		if state == windows.WAIT_OBJECT_0 {
			break
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	// PowerShell startup can race the engine's own orderly cleanup. Repeating
	// the narrowly owned removal is idempotent and also handles a transient CIM failure.
	for attempt := 0; attempt < 3; attempt++ {
		if err = removeNRPT(ctx, id); err == nil {
			return clearJournal(id)
		}
	}
	return fmt.Errorf("恢复本次 DNS 策略：%w", err)
}
