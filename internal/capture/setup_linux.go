package capture

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// HelperSetup keeps authentication and service checks off the UI thread. It
// never prompts for a password: the operating system owns authentication.
type HelperSetup struct {
	mu       sync.Mutex
	state    HelperSetupState
	closed   bool
	check    func(context.Context) error
	install  func() error
	onChange func()
	cancel   context.CancelFunc
}

type HelperSetupState struct {
	Checked    bool
	Busy       bool
	Installing bool
	Ready      bool
	Message    string
}

func NewHelperSetup(onChange func()) *HelperSetup {
	return &HelperSetup{check: HelperAvailable, install: installPackagedHelper, onChange: onChange}
}

func (s *HelperSetup) Snapshot() HelperSetupState { s.mu.Lock(); defer s.mu.Unlock(); return s.state }

func (s *HelperSetup) begin(install bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.state.Busy {
		return false
	}
	s.state.Busy, s.state.Installing = true, install
	if install {
		s.state.Message = "等待系统认证或安装完成，请在系统窗口输入密码。"
	} else {
		s.state.Message = "正在检查辅助服务…"
	}
	return true
}

func (s *HelperSetup) notify() {
	s.mu.Lock()
	closed, callback := s.closed, s.onChange
	s.mu.Unlock()
	if !closed && callback != nil {
		callback()
	}
}

func (s *HelperSetup) complete(err error) {
	s.mu.Lock()
	s.state.Busy, s.state.Installing, s.state.Checked = false, false, true
	s.state.Ready = err == nil
	if err == nil {
		s.state.Message = "辅助服务已就绪，可以启动软件接管项目。"
	} else {
		s.state.Message = err.Error()
	}
	s.cancel = nil
	s.mu.Unlock()
	s.notify()
}

func (s *HelperSetup) Check() bool {
	if !s.begin(false) {
		return false
	}
	s.mu.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	s.cancel = cancel
	if s.closed {
		cancel()
	}
	s.mu.Unlock()
	s.notify()
	go func() { defer cancel(); s.complete(s.check(ctx)) }()
	return true
}

// Installation is not cancelled halfway through a privileged transaction when
// the GUI closes. The system dialog can cancel authentication; once authorized,
// the installer finishes service recovery and replacement under its own lock.
func (s *HelperSetup) Install() bool {
	if !s.begin(true) {
		return false
	}
	s.notify()
	go func() {
		err := s.install()
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err = s.check(ctx)
			cancel()
			if err != nil {
				err = fmt.Errorf("安装已执行，但服务尚未就绪：%w", err)
			}
		}
		s.complete(err)
	}()
	return true
}

func (s *HelperSetup) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if s.cancel != nil {
		s.cancel()
	}
}

func installCommand(executable string, uid int) (*exec.Cmd, error) {
	if uid < 1 {
		return nil, errors.New("请以普通用户启动桌面应用，再通过系统窗口授权安装")
	}
	path, err := filepath.EvalSymlinks(executable)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(path)
	for _, name := range []string{"install-capture-helper.sh", "easyconnect-hub-capture@.service"} {
		st, err := os.Lstat(filepath.Join(dir, name))
		if err != nil || !st.Mode().IsRegular() {
			return nil, errors.New("当前目录缺少完整安装文件，请从完整 Linux 软件包启动应用")
		}
	}
	// 内部程序放在 core/，避免用户直接双击；拆分前的平铺布局仍兼容。
	if !packagedCaptureHelper(filepath.Join(dir, "core", "easyconnect-hub-capture")) &&
		!packagedCaptureHelper(filepath.Join(dir, "easyconnect-hub-capture")) {
		return nil, errors.New("当前目录缺少完整安装文件，请从完整 Linux 软件包启动应用")
	}
	return exec.Command("/usr/bin/pkexec", "--disable-internal-agent", "/usr/bin/bash", filepath.Join(dir, "install-capture-helper.sh"), "--uid", strconv.Itoa(uid)), nil
}

// packagedCaptureHelper reports whether path is the executable helper shipped
// in the bundle. The installer re-checks it; this only catches an incomplete
// extraction before asking for system authorization.
func packagedCaptureHelper(path string) bool {
	st, err := os.Lstat(path)
	return err == nil && st.Mode().IsRegular() && st.Mode()&0111 != 0
}

func installPackagedHelper() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd, err := installCommand(exe, os.Getuid())
	if err != nil {
		return err
	}
	// No stdin or shell interpolation. Installer output contains no login
	// data and is discarded; only a bounded, localized status reaches the GUI.
	cmd.Stdin = nil
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err = cmd.Run(); err == nil {
		return nil
	}
	var status *exec.ExitError
	if errors.As(err, &status) {
		switch status.ExitCode() {
		case 126:
			return errors.New("已取消系统认证；未执行本次安装")
		case 127:
			return errors.New("未获得系统授权；若没有认证窗口，请在软件包目录运行 sudo ./install-capture-helper.sh")
		case 75:
			return errors.New("另一个安装或卸载任务正在执行，请等待完成后重新检查")
		default:
			return errors.New("辅助服务安装未完成，请在软件包目录运行 sudo ./install-capture-helper.sh 查看具体原因")
		}
	}
	return errors.New("无法启动系统安装程序，请在软件包目录运行 sudo ./install-capture-helper.sh")
}
