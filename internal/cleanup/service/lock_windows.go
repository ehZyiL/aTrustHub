//go:build windows

package service

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// An OS-held lock survives neither a crash nor process exit. It serializes
// apply/restore across multiple Hub instances without stale PID files.
func lockMutations(root string) (func(), error) {
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	p, err := windows.UTF16PtrFromString(filepath.Join(root, ".mutation.lock"))
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, errors.New("另一项清理或恢复仍在运行，或无法锁定备份目录")
	}
	return func() { windows.CloseHandle(h) }, nil
}
