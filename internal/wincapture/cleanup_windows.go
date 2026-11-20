package wincapture

import (
	"errors"
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Keep the authenticated helper identity after closing its pipe. A broken
// control channel alone cannot establish that privileged cleanup has finished.
type helperTransport struct {
	*os.File
	id       string
	identity Identity
}

func (f *helperTransport) ConfirmCleanup() error {
	return confirmHelperCleanup(f.id, helperCleanupProbe{
		active:     func() (bool, error) { return helperIdentityActive(f.identity) },
		interfaces: net.Interfaces,
		journal: func() (bool, error) {
			key, err := registry.OpenKey(registry.LOCAL_MACHINE, recoveryRoot+`\`+f.id, registry.QUERY_VALUE|registry.WOW64_64KEY)
			if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
				return false, nil
			}
			if err != nil {
				return false, err
			}
			defer key.Close()
			return true, nil
		},
	})
}

type helperCleanupProbe struct {
	active     func() (bool, error)
	interfaces func() ([]net.Interface, error)
	journal    func() (bool, error)
}

func confirmHelperCleanup(id string, probe helperCleanupProbe) error {
	if !validID(id) {
		return errors.New("无法确认网络助手清理身份")
	}
	active, err := probe.active()
	if err != nil {
		return fmt.Errorf("确认网络助手退出：%w", err)
	}
	if active {
		return errors.New("网络助手仍在运行，等待退出后重试清理")
	}
	interfaces, err := probe.interfaces()
	if err != nil {
		return fmt.Errorf("确认接管网卡已移除：%w", err)
	}
	for _, iface := range interfaces {
		if iface.Name == "ECH-"+id[:12] {
			return errors.New("接管网卡尚未移除，请重试清理")
		}
	}
	// The elevated watchdog removes this journal only after compare-and-remove
	// DNS recovery succeeds. The desktop only reads it; it never skips recovery
	// or modifies another runtime's network settings to unlock the UI.
	pending, err := probe.journal()
	if err != nil {
		return fmt.Errorf("确认 DNS 恢复完成：%w", err)
	}
	if pending {
		return errors.New("DNS 恢复尚未完成，请重试清理")
	}
	return nil
}

func helperIdentityActive(expected Identity) (bool, error) {
	if expected.PID == 0 || expected.Created == 0 {
		return false, errors.New("缺少网络助手进程身份")
	}
	h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, expected.PID)
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer windows.CloseHandle(h)
	actual, err := processIdentity(h, expected.PID)
	if err != nil {
		return false, err
	}
	if actual != expected {
		return false, nil // The old process ended and its PID has been reused.
	}
	state, err := windows.WaitForSingleObject(h, 0)
	if err != nil {
		return false, err
	}
	switch state {
	case windows.WAIT_OBJECT_0:
		return false, nil
	case uint32(windows.WAIT_TIMEOUT):
		return true, nil
	default:
		return false, errors.New("网络助手进程状态未知")
	}
}
