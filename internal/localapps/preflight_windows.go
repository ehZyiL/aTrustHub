package localapps

import (
	"context"
	"errors"
	"fmt"
	"os"
	"unsafe"

	"github.com/ehZyiL/connect-hub/internal/model"
	"github.com/ehZyiL/connect-hub/internal/wincapture"
	"golang.org/x/sys/windows"
)

func checkCaptureProgram(ctx context.Context, p model.LocalApp) error {
	if err := wincapture.ValidateProgram(wincapture.Program{Executable: p.Executable, Args: p.Args, WorkDir: p.WorkDir}); err != nil {
		return err
	}
	target, err := os.Stat(p.Executable)
	if err != nil {
		return err
	}
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return fmt.Errorf("无法检查已有软件实例：%w", err)
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	err = windows.Process32First(snapshot, &entry)
	for err == nil {
		if err := ctx.Err(); err != nil {
			return err
		}
		process, openErr := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, entry.ProcessID)
		if openErr == nil {
			var path [32768]uint16
			n := uint32(len(path))
			readErr := windows.QueryFullProcessImageName(process, 0, &path[0], &n)
			windows.CloseHandle(process)
			if readErr == nil {
				if info, statErr := os.Stat(windows.UTF16ToString(path[:n])); statErr == nil && os.SameFile(target, info) {
					return fmt.Errorf("检测到此软件已有实例（PID %d）。请保存工作并退出已有实例，再从本应用重新启动", entry.ProcessID)
				}
			}
		}
		err = windows.Process32Next(snapshot, &entry)
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return fmt.Errorf("软件实例检查失败：%w", err)
	}
	return ctx.Err()
}
