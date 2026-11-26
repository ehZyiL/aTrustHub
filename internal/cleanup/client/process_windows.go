//go:build windows

package client

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func hide(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true} }

type child struct{ cmd *exec.Cmd }

func (c *child) Wait() error { return c.cmd.Wait() }
func (c *child) Kill() error { return c.cmd.Process.Kill() }

type elevatedChild struct{ handle windows.Handle }

func (c *elevatedChild) Wait() error {
	defer windows.CloseHandle(c.handle)
	if _, err := windows.WaitForSingleObject(c.handle, windows.INFINITE); err != nil {
		return err
	}
	var code uint32
	if err := windows.GetExitCodeProcess(c.handle, &code); err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("组件退出码 %d", code)
	}
	return nil
}
func (c *elevatedChild) Kill() error {
	return errors.New("不能强制终止正在修改系统的清理任务")
}

type shellExecuteInfo struct {
	Size                              uint32
	Mask                              uint32
	Window                            windows.Handle
	Verb, File, Parameters, Directory *uint16
	Show                              int32
	Instance                          windows.Handle
	IDList                            uintptr
	Class                             *uint16
	ClassKey                          windows.Handle
	HotKey                            uint32
	Icon                              uintptr
	Process                           windows.Handle
}

func launchProcess(exe string, args []string, elevated bool) (Process, error) {
	if !elevated || windows.GetCurrentProcessToken().IsElevated() {
		cmd := exec.Command(exe, args...)
		hide(cmd)
		if err := cmd.Start(); err != nil {
			return nil, err
		}
		return &child{cmd}, nil
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return nil, err
	}
	params, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(args))
	if err != nil {
		return nil, err
	}
	dir, err := windows.UTF16PtrFromString(filepath.Dir(exe))
	if err != nil {
		return nil, err
	}
	info := shellExecuteInfo{Mask: 0x40, Verb: verb, File: file, Parameters: params, Directory: dir, Show: 0}
	info.Size = uint32(unsafe.Sizeof(info))
	ret, _, callErr := windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteExW").Call(uintptr(unsafe.Pointer(&info)))
	if ret == 0 {
		if errors.Is(callErr, windows.ERROR_CANCELLED) {
			return nil, errors.New("用户取消了管理员授权，未执行清理")
		}
		return nil, fmt.Errorf("管理员授权或组件启动失败: %w", callErr)
	}
	if info.Process == 0 {
		return nil, errors.New("未获得清理进程句柄")
	}
	return &elevatedChild{info.Process}, nil
}
