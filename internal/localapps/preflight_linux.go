package localapps

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/ehZyiL/connect-hub/internal/model"
	"golang.org/x/sys/unix"
)

// checkCaptureProgram runs before acquiring DNS or capture leases. This is a
// best-effort restart check, not process authorization: executable wrappers,
// D-Bus activation and existing daemons still require application-specific
// handling. Never inspect command lines or signal an existing process here.
func checkCaptureProgram(ctx context.Context, p model.LocalApp) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	executable, err := filepath.EvalSymlinks(p.Executable)
	if err != nil {
		return fmt.Errorf("无法找到软件，请重新选择可执行文件：%w", err)
	}
	file, err := os.Stat(executable)
	if err != nil {
		return fmt.Errorf("无法读取软件文件：%w", err)
	}
	if !file.Mode().IsRegular() {
		return errors.New("请选择程序文件，不能使用目录或特殊文件")
	}
	if err := unix.Access(executable, unix.X_OK); err != nil {
		return errors.New("当前用户没有运行此软件的权限，请检查文件执行权限")
	}
	if p.WorkDir != "" {
		dir, err := os.Stat(p.WorkDir)
		if err != nil || !dir.IsDir() {
			return errors.New("工作目录不存在或不是目录，请重新选择")
		}
		if err := unix.Access(p.WorkDir, unix.X_OK); err != nil {
			return errors.New("当前用户无法进入所选工作目录")
		}
	}
	pid, err := runningExecutable(ctx, "/proc", os.Getuid(), executable, file)
	if err != nil {
		return fmt.Errorf("无法完成软件启动检查：%w", err)
	}
	if pid != 0 {
		return fmt.Errorf("检测到此软件已有实例（PID %d）。请保存工作并退出已有实例，再从本应用重新启动", pid)
	}
	return nil
}

func runningExecutable(ctx context.Context, proc string, uid int, executable string, file os.FileInfo) (int, error) {
	entries, err := os.ReadDir(proc)
	if err != nil {
		return 0, err
	}
	selfMount, _ := os.Readlink(filepath.Join(proc, "self/ns/mnt"))
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 || !entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue // A process may exit during enumeration.
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || int(stat.Uid) != uid {
			continue
		}
		path := filepath.Join(proc, entry.Name(), "exe")
		if live, err := os.Stat(path); err == nil && os.SameFile(file, live) {
			return pid, nil
		}
		target, err := os.Readlink(path)
		if err != nil {
			continue // Zombies and restricted processes have no readable exe.
		}
		// A deleted executable at this pathname can be the old instance after
		// an atomic upgrade. Only compare pathnames in the same mount namespace;
		// a container can have a different program at an identical pathname.
		if target == executable+" (deleted)" && selfMount != "" {
			if mount, err := os.Readlink(filepath.Join(proc, entry.Name(), "ns/mnt")); err == nil && mount == selfMount {
				return pid, nil
			}
		}
	}
	return 0, ctx.Err()
}
