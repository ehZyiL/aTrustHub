//go:build windows

package sangforclean

import (
	"fmt"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modshell32            = windows.NewLazySystemDLL("shell32.dll")
	procShellExecuteExW    = modshell32.NewProc("ShellExecuteExW")
)

type SHELLEXECUTEINFOW struct {
	CbSize         uint32
	FMask          uint32
	Hwnd           windows.Handle
	LpVerb         *uint16
	LpFile         *uint16
	LpParameters   *uint16
	LpDirectory    *uint16
	NShow          int32
	HInstApp       windows.Handle
	LpIDList       uintptr
	LpClass        *uint16
	HkeyClass      windows.Handle
	DwHotKey       uint32
	DUMMYUNIONNAME uintptr
	HProcess       windows.Handle
}

const (
	SEE_MASK_NOCLOSEPROCESS = 0x00000040
	SW_HIDE                 = 0
	SW_SHOWNORMAL           = 1
)

// IsElevated 检测当前进程是否拥有管理员特权
func IsElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// RunElevatedAndWait 通过 ShellExecuteExW 以管理员身份拉起进程并阻塞等待，返回其退出码
func RunElevatedAndWait(exePath string, args string, hide bool) (int, error) {
	verb, err := windows.UTF16PtrFromString("runas")
	if err != nil {
		return 4, err
	}

	file, err := windows.UTF16PtrFromString(exePath)
	if err != nil {
		return 4, err
	}

	params, err := windows.UTF16PtrFromString(args)
	if err != nil {
		return 4, err
	}

	dir, err := windows.UTF16PtrFromString(filepath.Dir(exePath))
	if err != nil {
		return 4, err
	}

	show := int32(SW_SHOWNORMAL)
	if hide {
		show = SW_HIDE
	}

	var sei SHELLEXECUTEINFOW
	sei.CbSize = uint32(unsafe.Sizeof(sei))
	sei.FMask = SEE_MASK_NOCLOSEPROCESS
	sei.LpVerb = verb
	sei.LpFile = file
	sei.LpParameters = params
	sei.LpDirectory = dir
	sei.NShow = show

	ret, _, callErr := procShellExecuteExW.Call(uintptr(unsafe.Pointer(&sei)))
	if ret == 0 {
		return 4, fmt.Errorf("提权启动被取消或失败: %v", callErr)
	}

	if sei.HProcess == 0 {
		return 0, nil
	}
	defer windows.CloseHandle(sei.HProcess)

	// 等待子进程退出
	_, err = windows.WaitForSingleObject(sei.HProcess, windows.INFINITE)
	if err != nil {
		return 1, err
	}

	var exitCode uint32
	if err := windows.GetExitCodeProcess(sei.HProcess, &exitCode); err != nil {
		return 1, err
	}

	return int(exitCode), nil
}
