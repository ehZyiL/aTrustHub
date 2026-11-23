//go:build windows

package sangforclean

import (
	"encoding/hex"
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

// UninstallWinsockProvider 安全卸载 Winsock Provider（调用系统标准 SPI API，失败自动降级至 netsh 重置）
func UninstallWinsockProvider(providerIdHex string, isNameSpace bool) error {
	guidBytes, err := hex.DecodeString(strings.TrimSpace(providerIdHex))
	if err != nil || len(guidBytes) != 16 {
		// 若无法解析 GUID，通过 netsh 重置兜底
		return NetshWinsockReset()
	}

	guid := (*windows.GUID)(unsafe.Pointer(&guidBytes[0]))
	failed := false

	if isNameSpace {
		ret, _, _ := procWSCUnInstallNameSpace.Call(uintptr(unsafe.Pointer(guid)))
		if ret != 0 {
			if procWSCUnInstallNameSpace32.Find() == nil {
				ret32, _, _ := procWSCUnInstallNameSpace32.Call(uintptr(unsafe.Pointer(guid)))
				if ret32 != 0 {
					failed = true
				}
			} else {
				failed = true
			}
		}
	} else {
		var errCode int32
		ret, _, _ := procWSCDeinstallProvider.Call(uintptr(unsafe.Pointer(guid)), uintptr(unsafe.Pointer(&errCode)))
		if ret != 0 {
			if procWSCDeinstallProvider32.Find() == nil {
				ret32, _, _ := procWSCDeinstallProvider32.Call(uintptr(unsafe.Pointer(guid)), uintptr(unsafe.Pointer(&errCode)))
				if ret32 != 0 {
					failed = true
				}
			} else {
				failed = true
			}
		}
	}

	// 若 SPI API 卸载失败，降级执行系统级重置
	if failed {
		return NetshWinsockReset()
	}

	return nil
}

// NetshWinsockReset 执行系统标准 winsock 重置
func NetshWinsockReset() error {
	cmd := exec.Command("netsh.exe", "winsock", "reset")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run()
}
