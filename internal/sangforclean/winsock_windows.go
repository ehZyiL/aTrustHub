//go:build windows

package sangforclean

import (
	"encoding/hex"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modWs2_32                   = windows.NewLazySystemDLL("ws2_32.dll")
	procWSCUnInstallNameSpace   = modWs2_32.NewProc("WSCUnInstallNameSpace")
	procWSCDeinstallProvider    = modWs2_32.NewProc("WSCDeinstallProvider")
	procWSCUnInstallNameSpace32 = modWs2_32.NewProc("WSCUnInstallNameSpace32")
	procWSCDeinstallProvider32  = modWs2_32.NewProc("WSCDeinstallProvider32")
)

// UninstallWinsockProvider 精准卸载单项 Winsock Provider（严禁自动全局 netsh winsock reset）
func UninstallWinsockProvider(providerIdHex string, isNameSpace bool) error {
	guidBytes, err := hex.DecodeString(strings.TrimSpace(providerIdHex))
	if err != nil || len(guidBytes) != 16 {
		return fmt.Errorf("无效的 Provider GUID 字节: %q", providerIdHex)
	}

	guid := (*windows.GUID)(unsafe.Pointer(&guidBytes[0]))

	if isNameSpace {
		ret, _, callErr := procWSCUnInstallNameSpace.Call(uintptr(unsafe.Pointer(guid)))
		if ret != 0 {
			// 若 64 位调用失败且存在 32 位导出，尝试 32 位视图
			if procWSCUnInstallNameSpace32.Find() == nil {
				ret32, _, callErr32 := procWSCUnInstallNameSpace32.Call(uintptr(unsafe.Pointer(guid)))
				if ret32 != 0 {
					return fmt.Errorf("WSCUnInstallNameSpace 失败 (64bit err: %v, 32bit err: %v)", callErr, callErr32)
				}
			} else {
				return fmt.Errorf("WSCUnInstallNameSpace 失败: %v", callErr)
			}
		}
	} else {
		var errCode int32
		ret, _, callErr := procWSCDeinstallProvider.Call(uintptr(unsafe.Pointer(guid)), uintptr(unsafe.Pointer(&errCode)))
		if ret != 0 {
			if procWSCDeinstallProvider32.Find() == nil {
				ret32, _, callErr32 := procWSCDeinstallProvider32.Call(uintptr(unsafe.Pointer(guid)), uintptr(unsafe.Pointer(&errCode)))
				if ret32 != 0 {
					return fmt.Errorf("WSCDeinstallProvider 失败 (errCode=%d, 64bit err: %v, 32bit err: %v)", errCode, callErr, callErr32)
				}
			} else {
				return fmt.Errorf("WSCDeinstallProvider 失败 (errCode=%d): %v", errCode, callErr)
			}
		}
	}

	return nil
}

// NetshWinsockReset 仅供外部显式调用或用户手动确认时使用，绝不自动隐式触发
func NetshWinsockReset() error {
	cmd := exec.Command("netsh.exe", "winsock", "reset")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run()
}
