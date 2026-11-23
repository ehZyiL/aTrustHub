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
	modWs2_32                  = windows.NewLazySystemDLL("ws2_32.dll")
	procWSCUnInstallNameSpace  = modWs2_32.NewProc("WSCUnInstallNameSpace")
	procWSCDeinstallProvider   = modWs2_32.NewProc("WSCDeinstallProvider")
	procWSCUnInstallNameSpace32 = modWs2_32.NewProc("WSCUnInstallNameSpace32")
	procWSCDeinstallProvider32  = modWs2_32.NewProc("WSCDeinstallProvider32")
)

// UninstallWinsockProvider 安全卸载 Winsock Provider（调用系统标准 SPI API）
func UninstallWinsockProvider(providerIdHex string, isNameSpace bool) error {
	guidBytes, err := hex.DecodeString(strings.TrimSpace(providerIdHex))
	if err != nil || len(guidBytes) != 16 {
		// 若无法解析 GUID，尝试通过 netsh 重置兜底
		return NetshWinsockReset()
	}

	guid := (*windows.GUID)(unsafe.Pointer(&guidBytes[0]))

	if isNameSpace {
		ret, _, _ := procWSCUnInstallNameSpace.Call(uintptr(unsafe.Pointer(guid)))
		if ret != 0 {
			var errno int32
			// 尝试 32 位视图
			if procWSCUnInstallNameSpace32.Find() == nil {
				_, _, _ = procWSCUnInstallNameSpace32.Call(uintptr(unsafe.Pointer(guid)))
			}
			_ = errno
		}
	} else {
		var errCode int32
		ret, _, _ := procWSCDeinstallProvider.Call(uintptr(unsafe.Pointer(guid)), uintptr(unsafe.Pointer(&errCode)))
		if ret != 0 {
			if procWSCDeinstallProvider32.Find() == nil {
				_, _, _ = procWSCDeinstallProvider32.Call(uintptr(unsafe.Pointer(guid)), uintptr(unsafe.Pointer(&errCode)))
			}
		}
	}

	return nil
}

// NetshWinsockReset 执行系统标准 winsock 重置
func NetshWinsockReset() error {
	cmd := exec.Command("netsh.exe", "winsock", "reset")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run()
}
