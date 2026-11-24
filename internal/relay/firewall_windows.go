//go:build windows

package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// This file is the privileged boundary for firewall rules.
//
// The desktop never runs netsh itself: an unprivileged process cannot create an
// inbound rule, and pretending to try is what the review found. Instead the
// desktop launches the already-shipped, already-elevated capture helper with a
// one-shot, closed-set operation. The helper validates every argument, performs
// exactly create/query/delete for this app's own rule name, and reports the full
// attribute set it read back.

// FirewallInfo describes what this build offers on Windows.
func FirewallInfo() FirewallGuidance {
	return FirewallGuidance{
		Platform:  "windows",
		Automatic: true,
		Lines: []string{
			"Windows 防火墙可能拦截局域网入站连接。",
			"「允许局域网连接」只创建一条本程序、当前端口、专用网络、所选局域网子网的最小规则，需要系统授权。",
			"取消系统授权不会修改任何既有规则，分享保持原状。",
		},
	}
}

// ElevatedFirewall runs firewall operations through the elevated helper.
type ElevatedFirewall struct {
	// helper is the elevated executable. Empty means "find it next to this
	// program", which is the packaged layout.
	helper string
	// resultTimeout bounds the wait for the helper after the prompt returns.
	resultTimeout time.Duration
}

// NewElevatedFirewall returns the production executor.
func NewElevatedFirewall() FirewallExecutor {
	return &ElevatedFirewall{resultTimeout: FirewallOpBudget}
}

// Run performs one firewall operation.
//
// Reading the rule set needs no privilege, so a query runs in-process: that is
// what startup verification uses, and it must never pop a UAC prompt. Creating
// and deleting a rule are privileged, so those go through the elevated helper.
func (e *ElevatedFirewall) Run(ctx context.Context, op FirewallOperation) (FirewallResult, error) {
	if err := op.Validate(); err != nil {
		return FirewallResult{Outcome: FirewallFailed, Detail: err.Error()}, err
	}
	if op.Op == FirewallOpQuery {
		return executeFirewallOperation(op), nil
	}
	helper, err := e.helperPath()
	if err != nil {
		return FirewallResult{Outcome: FirewallFailed, Detail: err.Error()}, err
	}
	dir, err := os.MkdirTemp("", "connect-hub-firewall-")
	if err != nil {
		return FirewallResult{Outcome: FirewallFailed, Detail: err.Error()}, err
	}
	defer os.RemoveAll(dir)
	opPath := filepath.Join(dir, "op.json")
	resultPath := filepath.Join(dir, "result.json")
	data, err := json.Marshal(op)
	if err != nil {
		return FirewallResult{Outcome: FirewallFailed, Detail: err.Error()}, err
	}
	if err := os.WriteFile(opPath, data, 0o600); err != nil {
		return FirewallResult{Outcome: FirewallFailed, Detail: err.Error()}, err
	}

	identity, err := selfIdentity()
	if err != nil {
		return FirewallResult{Outcome: FirewallFailed, Detail: "无法读取本进程身份：" + err.Error()}, err
	}
	params := windows.ComposeCommandLine([]string{
		"--firewall-op", opPath,
		"--firewall-result", resultPath,
		"--parent", strconv.FormatUint(uint64(identity.PID), 10),
		"--created", strconv.FormatUint(identity.Created, 10),
	})
	verb, _ := windows.UTF16PtrFromString("runas")
	helper16, _ := windows.UTF16PtrFromString(helper)
	params16, _ := windows.UTF16PtrFromString(params)
	dir16, _ := windows.UTF16PtrFromString(filepath.Dir(helper))
	verbPtr := (*uint16)(unsafe.Pointer(verb))
	exeInfo := shellExecuteInfo{
		cbSize:       uint32(unsafe.Sizeof(shellExecuteInfo{})),
		fMask:        seeMaskNoCloseProcess | seeMaskNoAsync,
		lpVerb:       verbPtr,
		lpFile:       helper16,
		lpParameters: params16,
		lpDirectory:  dir16,
		nShow:        windows.SW_HIDE,
	}
	ok, _, lastErr := procShellExecuteExW.Call(uintptr(unsafe.Pointer(&exeInfo)))
	if ok == 0 {
		if lastErr == syscall.Errno(windows.ERROR_CANCELLED) {
			// The user declined the elevation prompt. Nothing was executed.
			return FirewallResult{Outcome: FirewallCanceled, Detail: "已取消系统授权"}, nil
		}
		if lastErr == syscall.Errno(windows.ERROR_ACCESS_DENIED) {
			return FirewallResult{Outcome: FirewallDenied, Detail: "系统拒绝授权"}, nil
		}
		return FirewallResult{Outcome: FirewallDenied, Detail: "无法请求系统授权：" + lastErr.Error()}, nil
	}
	if exeInfo.hProcess != 0 {
		defer windows.CloseHandle(exeInfo.hProcess)
	}

	// Wait for the helper, but never longer than the budget: an unanswered UAC
	// prompt must not hang the share lifecycle.
	deadline := time.Now().Add(e.resultTimeout)
	for {
		state, err := windows.WaitForSingleObject(exeInfo.hProcess, 250)
		if err != nil {
			return FirewallResult{Outcome: FirewallFailed, Detail: "等待系统授权失败：" + err.Error()}, err
		}
		if state == windows.WAIT_OBJECT_0 {
			break
		}
		select {
		case <-ctx.Done():
			_ = windows.TerminateProcess(exeInfo.hProcess, 1)
			return FirewallResult{Outcome: FirewallCanceled, Detail: "操作已取消"}, ctx.Err()
		default:
		}
		if time.Now().After(deadline) {
			_ = windows.TerminateProcess(exeInfo.hProcess, 1)
			return FirewallResult{Outcome: FirewallTimeout, Detail: "系统授权超时"}, nil
		}
	}
	return readFirewallResult(resultPath)
}

// helperPath finds the elevated helper in the packaged layout.
func (e *ElevatedFirewall) helperPath() (string, error) {
	if e.helper != "" {
		return e.helper, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return "", errors.New("无法定位主程序")
	}
	base := filepath.Dir(exe)
	for _, candidate := range []string{
		filepath.Join(base, "core", "connect-hub-capture.exe"),
		filepath.Join(base, "connect-hub-capture.exe"),
	} {
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			return candidate, nil
		}
	}
	return "", errors.New("缺少 Windows 网络助手，请解压完整安装包（connect-hub-capture.exe 位于 core 目录）")
}

// readFirewallResult decodes the helper's answer. A missing or unreadable answer
// is an unknown outcome, never a success.
func readFirewallResult(path string) (FirewallResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return FirewallResult{Outcome: FirewallFailed, Detail: "系统助手未返回结果，规则状态未知"}, nil
		}
		return FirewallResult{Outcome: FirewallFailed, Detail: err.Error()}, err
	}
	var result FirewallResult
	data = bytes.TrimPrefix(data, utf8BOM)
	if err := json.Unmarshal(data, &result); err != nil {
		return FirewallResult{Outcome: FirewallFailed, Detail: "系统助手返回的结果无法读取"}, nil
	}
	if result.Outcome == "" {
		result.Outcome = FirewallFailed
	}
	return result, nil
}

// selfIdentity returns this process's pid and creation time, which the helper
// checks before doing anything privileged.
func selfIdentity() (ProcessIdentity, error) {
	pid := uint32(os.Getpid())
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ProcessIdentity{}, err
	}
	defer windows.CloseHandle(handle)
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(handle, &creation, &exit, &kernel, &user); err != nil {
		return ProcessIdentity{}, err
	}
	return ProcessIdentity{PID: pid, Created: uint64(creation.HighDateTime)<<32 | uint64(creation.LowDateTime)}, nil
}

// VerifyLaunchCaller checks that the process which asked for this privileged
// operation is this installation's desktop program.
//
// It deliberately does not require a parent/child relationship: when a process is
// created through UAC, Windows creates it from the AppInfo service, so the parent
// of an elevated helper is not the desktop. Requiring that would make the whole
// feature fail on real machines. What is checked instead is that the claimed
// identity still names a live process whose image is the connect-hub executable
// installed next to this helper — the only program that would legitimately ask.
func VerifyLaunchCaller(expected ProcessIdentity) error {
	if expected.PID == 0 || expected.Created == 0 {
		return errors.New("缺少调用方进程身份")
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, expected.PID)
	if err != nil {
		return errors.New("调用方进程已不存在")
	}
	defer windows.CloseHandle(handle)
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(handle, &creation, &exit, &kernel, &user); err != nil {
		return errors.New("无法读取调用方进程信息")
	}
	created := uint64(creation.HighDateTime)<<32 | uint64(creation.LowDateTime)
	if created != expected.Created {
		// The pid was reused by another process.
		return errors.New("调用方进程身份不符，拒绝执行")
	}
	image, err := processImagePath(handle)
	if err != nil {
		return errors.New("无法确认调用方程序路径")
	}
	if desktop := desktopProgramPath(); desktop != "" {
		if !sameProgram(image, desktop) {
			return errors.New("调用方不是本程序的桌面进程，拒绝执行")
		}
		return nil
	}
	// The packaged layout was not recognised (a development build, for example).
	// Require at least the same installation directory instead of refusing
	// everything.
	if !sameInstallTree(image) {
		return errors.New("调用方不在本程序的安装目录内，拒绝执行")
	}
	return nil
}

// sameInstallTree reports whether image lives next to this helper or one level up
// (core/connect-hub-capture.exe → ../connect-hub.exe).
func sameInstallTree(image string) bool {
	self, err := os.Executable()
	if err != nil {
		return false
	}
	base := filepath.Dir(self)
	imageDir := filepath.Dir(filepath.Clean(image))
	return strings.EqualFold(imageDir, filepath.Clean(base)) ||
		strings.EqualFold(imageDir, filepath.Dir(filepath.Clean(base)))
}

// processImagePath returns the executable path of a process handle.
func processImagePath(handle windows.Handle) (string, error) {
	buf := make([]uint16, windows.MAX_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(handle, 0, &buf[0], &size); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:size]), nil
}

// desktopProgramPath is the connect-hub executable that ships next to the helper
// (core/connect-hub-capture.exe → ../connect-hub.exe).
func desktopProgramPath() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	base := filepath.Dir(exe)
	for _, candidate := range []string{
		filepath.Join(base, "..", "connect-hub.exe"),
		filepath.Join(base, "connect-hub.exe"),
	} {
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			return candidate
		}
	}
	return ""
}

// sameProgram compares two paths the way Windows does: case-insensitive, and
// tolerant of 8.3 short names or a trailing separator.
func sameProgram(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	ca, errA := filepath.Abs(a)
	cb, errB := filepath.Abs(b)
	if errA != nil || errB != nil {
		return false
	}
	return strings.EqualFold(filepath.Clean(ca), filepath.Clean(cb))
}

// ProcessIdentity is the pid + creation time pair that ties a launched helper to
// the process that launched it.
type ProcessIdentity struct {
	PID     uint32
	Created uint64
}

// shellExecuteInfo mirrors SHELLEXECUTEINFOW.
type shellExecuteInfo struct {
	cbSize         uint32
	fMask          uint32
	hwnd           windows.Handle
	lpVerb         *uint16
	lpFile         *uint16
	lpParameters   *uint16
	lpDirectory    *uint16
	nShow          int32
	hInstApp       windows.Handle
	lpIDList       uintptr
	lpClass        *uint16
	hkeyClass      windows.Handle
	dwHotKey       uint32
	hIconOrMonitor windows.Handle
	hProcess       windows.Handle
}

const (
	seeMaskNoCloseProcess = 0x00000040
	seeMaskNoAsync        = 0x00000100
)

var (
	shell32             = windows.NewLazySystemDLL("shell32.dll")
	procShellExecuteExW = shell32.NewProc("ShellExecuteExW")
)

// ---- elevated helper side -------------------------------------------------

// FirewallHelperMain is the privileged entry point: it validates its arguments,
// performs exactly one closed-set operation and writes a structured result.
//
// It refuses to run unelevated (it is launched with runas) and refuses any rule
// name this app did not create, so it cannot be used as a general firewall tool.
func FirewallHelperMain(opPath, resultPath string) error {
	token := windows.GetCurrentProcessToken()
	if !token.IsElevated() {
		return errors.New("防火墙操作需要管理员权限")
	}
	data, err := os.ReadFile(opPath)
	if err != nil {
		return err
	}
	var op FirewallOperation
	if err := json.Unmarshal(data, &op); err != nil {
		return errors.New("防火墙操作参数无法读取")
	}
	if err := op.Validate(); err != nil {
		return err
	}
	result := executeFirewallOperation(op)
	out, err := json.Marshal(result)
	if err != nil {
		return err
	}
	tmp := resultPath + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, resultPath)
}

// executeFirewallOperation runs the script above and maps its JSON answer.
func executeFirewallOperation(op FirewallOperation) FirewallResult {
	result := FirewallResult{OperationID: op.OperationID, Op: op.Op, Outcome: FirewallFailed}
	dir, err := os.MkdirTemp("", "connect-hub-fw-")
	if err != nil {
		result.Detail = err.Error()
		return result
	}
	defer os.RemoveAll(dir)
	opPath := filepath.Join(dir, "op.json")
	outPath := filepath.Join(dir, "result.json")
	data, err := json.Marshal(op)
	if err != nil {
		result.Detail = err.Error()
		return result
	}
	if err := os.WriteFile(opPath, data, 0o600); err != nil {
		result.Detail = err.Error()
		return result
	}
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", psFirewallScript)
	// A GUI process has no console: keep the helper invisible instead of letting
	// Windows allocate one.
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	cmd.Env = append(os.Environ(),
		"CONNECT_HUB_FW_OP="+opPath,
		"CONNECT_HUB_FW_OUT="+outPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		result.Detail = strings.TrimSpace(string(out))
		if result.Detail == "" {
			result.Detail = err.Error()
		}
		return result
	}
	data, readErr := os.ReadFile(outPath)
	if readErr != nil {
		result.Detail = "规则结果无法读取：" + readErr.Error()
		return result
	}
	parsed, parseErr := ParseFirewallScriptAnswer(data)
	parsed.OperationID = op.OperationID
	parsed.Op = op.Op
	parsed.Rule = op.Rule
	if parseErr != nil {
		parsed.Detail = parseErr.Error()
		parsed.Outcome = FirewallFailed
	}
	return parsed
}
