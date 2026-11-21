package wincapture

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
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

const pipePrefix = `\\.\pipe\EasyConnectHub-Capture-`

var consentPrompt = elevationPrompt{busy: make(chan struct{}, 1)}

func randomID() (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes[:]), nil
}

func validID(id string) bool {
	if len(id) != 32 {
		return false
	}
	b, err := hex.DecodeString(id)
	return err == nil && len(b) == 16 && strings.ToLower(id) == id
}

// The desktop creates a single-instance, local-only pipe before UAC. Both
// endpoints verify the other's OS process identity. Secrets use this pipe,
// never the command line, registry, environment or a temporary config file.
func startHelper(ctx context.Context) (*helperTransport, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if windows.GetCurrentProcessToken().IsElevated() {
		return nil, errors.New("请以普通用户运行主程序")
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, windowsError("定位主程序", err)
	}
	helper, ok := helperPath(exe)
	if !ok {
		return nil, errors.New("缺少 Windows 网络助手，请解压完整安装包（easyconnect-hub-capture.exe 位于 core 目录）")
	}
	if err := checkHelperProtocol(ctx, helper); err != nil {
		return nil, err
	}
	id, err := randomID()
	if err != nil {
		return nil, fmt.Errorf("生成网络助手通道标识：%w", err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, windowsError("读取当前用户 GetTokenInformation", err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return nil, windowsError("创建控制管道安全描述符", err)
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	name := pipePrefix + id
	name16, _ := windows.UTF16PtrFromString(name)
	h, err := windows.CreateNamedPipe(name16, windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_OVERLAPPED|windows.FILE_FLAG_FIRST_PIPE_INSTANCE,
		windows.PIPE_TYPE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS, 1, maxFrame, maxFrame, 0, &sa)
	if err != nil {
		return nil, windowsError("创建控制管道 CreateNamedPipe", err)
	}
	owned := true
	defer func() {
		if owned {
			windows.CloseHandle(h)
		}
	}()
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, windowsError("创建管道连接事件 CreateEvent", err)
	}
	defer windows.CloseHandle(event)
	overlap := windows.Overlapped{HEvent: event}
	err = windows.ConnectNamedPipe(h, &overlap)
	if err != nil && err != windows.ERROR_IO_PENDING && err != windows.ERROR_PIPE_CONNECTED {
		return nil, windowsError("等待助手连接 ConnectNamedPipe", err)
	}
	pending := err == windows.ERROR_IO_PENDING
	if pending {
		defer func() {
			if pending {
				_ = windows.CancelIoEx(h, &overlap)
				var n uint32
				_ = windows.GetOverlappedResult(h, &overlap, &n, true)
			}
		}()
	}
	identity, err := processIdentity(windows.CurrentProcess(), uint32(os.Getpid()))
	if err != nil {
		return nil, fmt.Errorf("读取主程序身份：%w", err)
	}
	params := windows.ComposeCommandLine([]string{"--pipe", id, "--parent", strconv.FormatUint(uint64(identity.PID), 10), "--created", strconv.FormatUint(identity.Created, 10)})
	verb16, _ := windows.UTF16PtrFromString("runas")
	helper16, _ := windows.UTF16PtrFromString(helper)
	params16, _ := windows.UTF16PtrFromString(params)
	dir16, _ := windows.UTF16PtrFromString(filepath.Dir(helper))
	if err = consentPrompt.run(ctx, func() error {
		return windowsError("ShellExecute(runas)", windows.ShellExecute(0, verb16, helper16, params16, dir16, windows.SW_HIDE))
	}); err != nil {
		return nil, fmt.Errorf("管理员授权未完成：%w", err)
	}
	for pending {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		state, err := windows.WaitForSingleObject(event, 50)
		if err != nil {
			return nil, windowsError("等待管道连接 WaitForSingleObject", err)
		}
		if state == windows.WAIT_OBJECT_0 {
			var n uint32
			err = windows.GetOverlappedResult(h, &overlap, &n, true)
			if err == nil {
				pending = false
			} else if !errors.Is(err, windows.ERROR_IO_INCOMPLETE) {
				return nil, windowsError("完成管道连接 GetOverlappedResult", err)
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var pid uint32
	if err = windows.GetNamedPipeClientProcessId(h, &pid); err != nil {
		return nil, windowsError("确认助手进程 GetNamedPipeClientProcessId", err)
	}
	peer, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return nil, windowsError("读取助手身份 OpenProcess", err)
	}
	defer windows.CloseHandle(peer)
	if err = verifyExecutable(peer, filepath.Dir(helper)); err != nil {
		return nil, fmt.Errorf("校验网络助手文件身份：%w", err)
	}
	var token windows.Token
	if err = windows.OpenProcessToken(peer, windows.TOKEN_QUERY, &token); err != nil {
		return nil, windowsError("校验助手权限 OpenProcessToken", err)
	}
	defer token.Close()
	if !token.IsElevated() {
		return nil, errors.New("网络助手未获管理员权限")
	}
	helperIdentity, err := processIdentity(peer, pid)
	if err != nil {
		return nil, fmt.Errorf("记录网络助手身份：%w", err)
	}
	f := os.NewFile(uintptr(h), name)
	if err = f.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		f.Close()
		owned = false
		return nil, windowsError("设置助手管道超时 SetDeadline", err)
	}
	owned = false
	return &helperTransport{File: f, id: id, identity: helperIdentity}, nil
}

func checkHelperProtocol(ctx context.Context, helper string) error {
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(probeCtx, helper, "--protocol-version")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.WaitDelay = time.Second
	output, err := cmd.Output()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil || strings.TrimSpace(string(output)) != strconv.Itoa(ProtocolVersion) {
		return fmt.Errorf("Windows 网络助手版本不匹配或无法校验（需要协议 v%d），请重新解压完整安装包（easyconnect-hub-capture.exe 位于 core 目录）", ProtocolVersion)
	}
	return nil
}

func connectDesktop(ctx context.Context, id string, expected Identity) (*os.File, windows.Handle, error) {
	if !validID(id) || expected.PID == 0 || expected.Created == 0 || !windows.GetCurrentProcessToken().IsElevated() {
		return nil, 0, errors.New("网络助手启动参数或权限无效")
	}
	parent, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_DUP_HANDLE|windows.SYNCHRONIZE, false, expected.PID)
	if err != nil {
		return nil, 0, err
	}
	ok := false
	defer func() {
		if !ok {
			windows.CloseHandle(parent)
		}
	}()
	actual, err := processIdentity(parent, expected.PID)
	if err != nil || actual != expected {
		return nil, 0, errors.New("主程序身份已变更")
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, 0, err
	}
	if err = verifyExecutable(parent, filepath.Dir(exe), bundleRoot(exe)); err != nil {
		return nil, 0, err
	}
	name := pipePrefix + id
	name16, _ := windows.UTF16PtrFromString(name)
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	h, err := windows.CreateFile(name16, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
	if err != nil {
		return nil, 0, err
	}
	var server uint32
	if err = windows.GetNamedPipeServerProcessId(h, &server); err != nil || server != expected.PID {
		windows.CloseHandle(h)
		return nil, 0, errors.New("主程序控制通道身份不匹配")
	}
	f := os.NewFile(uintptr(h), name)
	if err = f.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		f.Close()
		return nil, 0, err
	}
	ok = true
	return f, parent, nil
}

// verifyExecutable accepts a parent whose image directory is any of the
// bundle layouts that hold easyconnect-hub.exe. Naming the executable is
// deliberately avoided: users may copy or rename the desktop app, but the
// helper must still ship in the same bundle.
func verifyExecutable(process windows.Handle, allowed ...string) error {
	var path [32768]uint16
	n := uint32(len(path))
	if err := windows.QueryFullProcessImageName(process, 0, &path[0], &n); err != nil {
		return windowsError("QueryFullProcessImageName", err)
	}
	parentDir := filepath.Dir(windows.UTF16ToString(path[:n]))
	for _, dir := range allowed {
		if dir != "" && strings.EqualFold(parentDir, dir) {
			return nil
		}
	}
	return errors.New("网络助手与主程序必须来自同一安装目录")
}
