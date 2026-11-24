//go:build windows

package relay

import (
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

// Run launches the helper for one operation and waits for its structured answer.
func (e *ElevatedFirewall) Run(ctx context.Context, op FirewallOperation) (FirewallResult, error) {
	if err := op.Validate(); err != nil {
		return FirewallResult{Outcome: FirewallFailed, Detail: err.Error()}, err
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

// parentProcessIdentity returns this process's parent, which for an elevated
// helper is the desktop that launched it.
func parentProcessIdentity() (ProcessIdentity, bool) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return ProcessIdentity{}, false
	}
	defer windows.CloseHandle(snap)
	self := uint32(os.Getpid())
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	for err = windows.Process32First(snap, &entry); err == nil; err = windows.Process32Next(snap, &entry) {
		if entry.ProcessID != self {
			continue
		}
		parent := entry.ParentProcessID
		if parent == 0 {
			return ProcessIdentity{}, false
		}
		handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, parent)
		if err != nil {
			return ProcessIdentity{}, false
		}
		defer windows.CloseHandle(handle)
		var creation, exit, kernel, user windows.Filetime
		if err := windows.GetProcessTimes(handle, &creation, &exit, &kernel, &user); err != nil {
			return ProcessIdentity{}, false
		}
		return ProcessIdentity{PID: parent, Created: uint64(creation.HighDateTime)<<32 | uint64(creation.LowDateTime)}, true
	}
	return ProcessIdentity{}, false
}

// VerifyLaunchParent makes the helper usable only by the desktop that launched
// it, so it cannot be turned into a general "create a firewall rule" tool.
func VerifyLaunchParent(expected ProcessIdentity) error {
	actual, ok := parentProcessIdentity()
	if !ok {
		return errors.New("无法确认调用方进程身份")
	}
	if actual != expected {
		return errors.New("调用方进程身份不符，拒绝执行")
	}
	return nil
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

// psFirewallScript is the only script this helper runs. The operation arrives as
// a JSON file and every value is passed to a cmdlet as a parameter, so no user
// text is ever interpolated into a command line.
const psFirewallScript = `
$ErrorActionPreference = 'Stop'
$op = Get-Content -Raw -LiteralPath $env:CONNECT_HUB_FW_OP | ConvertFrom-Json
function Get-RuleState($name) {
  $r = Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
  if ($null -eq $r) { return $null }
  $app  = $r | Get-NetFirewallApplicationFilter
  $port = $r | Get-NetFirewallPortFilter
  $addr = $r | Get-NetFirewallAddressFilter
  return [pscustomobject]@{
    name      = [string]$r.DisplayName
    direction = [string]$r.Direction
    action    = [string]$r.Action
    enabled   = [bool]$r.Enabled
    profile   = [string]$r.Profile
    program   = [string]$app.Program
    protocol  = [string]$port.Protocol
    localPort = [string]$port.LocalPort
    remote    = [string]($addr.RemoteAddress -join ',')
  }
}
$result = [ordered]@{ outcome = 'failed'; detail = ''; state = $null }
try {
  switch ($op.op) {
    'apply' {
      $rule = $op.rule
      $existing = Get-NetFirewallRule -DisplayName $rule.id -ErrorAction SilentlyContinue
      if ($null -ne $existing) { Remove-NetFirewallRule -DisplayName $rule.id }
      $profileArg = @($rule.profile -split ',' | ForEach-Object { $_.Trim() })
      $params = @{
        DisplayName = $rule.id
        Direction   = 'Inbound'
        Action      = 'Allow'
        Program     = $rule.programPath
        Protocol    = 'TCP'
        LocalPort   = [int]$rule.port
        Profile     = $profileArg
        Enabled     = 'True'
      }
      if ($rule.remoteIp) { $params['RemoteAddress'] = $rule.remoteIp }
      New-NetFirewallRule @params | Out-Null
      $state = Get-RuleState $rule.id
      if ($null -eq $state) { $result.outcome = 'failed'; $result.detail = '规则创建后读不到' }
      else { $result.outcome = 'created'; $result.state = $state }
    }
    'query' {
      $state = Get-RuleState $op.ruleId
      if ($null -eq $state) { $result.outcome = 'absent' }
      else { $result.outcome = 'present'; $result.state = $state }
    }
    'delete' {
      $existing = Get-NetFirewallRule -DisplayName $op.ruleId -ErrorAction SilentlyContinue
      if ($null -eq $existing) { $result.outcome = 'absent' }
      else {
        Remove-NetFirewallRule -DisplayName $op.ruleId
        $state = Get-RuleState $op.ruleId
        if ($null -eq $state) { $result.outcome = 'removed' }
        else { $result.outcome = 'failed'; $result.detail = '规则删除后仍然存在' }
      }
    }
    default { $result.outcome = 'failed'; $result.detail = '不支持的操作' }
  }
} catch {
  $result.outcome = 'failed'
  $result.detail = $_.Exception.Message
}
$result | ConvertTo-Json -Compress -Depth 5 | Set-Content -LiteralPath $env:CONNECT_HUB_FW_OUT -Encoding UTF8
`

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
	var scriptAnswer struct {
		Outcome string `json:"outcome"`
		Detail  string `json:"detail"`
		State   *struct {
			Name      string `json:"name"`
			Direction string `json:"direction"`
			Action    string `json:"action"`
			Enabled   bool   `json:"enabled"`
			Profile   string `json:"profile"`
			Program   string `json:"program"`
			Protocol  string `json:"protocol"`
			LocalPort string `json:"localPort"`
			Remote    string `json:"remote"`
		} `json:"state"`
	}
	if err := json.Unmarshal(data, &scriptAnswer); err != nil {
		result.Detail = "规则结果无法解析"
		return result
	}
	result.Outcome = scriptAnswer.Outcome
	result.Detail = scriptAnswer.Detail
	if scriptAnswer.State != nil {
		result.State = FirewallRuleState{
			Name:          scriptAnswer.State.Name,
			Direction:     scriptAnswer.State.Direction,
			Action:        scriptAnswer.State.Action,
			Enabled:       scriptAnswer.State.Enabled,
			Profile:       scriptAnswer.State.Profile,
			Program:       scriptAnswer.State.Program,
			Protocol:      scriptAnswer.State.Protocol,
			LocalPort:     scriptAnswer.State.LocalPort,
			RemoteAddress: scriptAnswer.State.Remote,
		}
	}
	if result.Outcome == "" {
		result.Outcome = FirewallFailed
	}
	return result
}
