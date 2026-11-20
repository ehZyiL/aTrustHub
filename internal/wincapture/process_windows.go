package wincapture

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var isProcessInJob = windows.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob")

type Program struct {
	Executable string
	Args       []string
	WorkDir    string
}

// Process first reserves an empty job. The helper registers that job before
// Launch atomically creates the application inside it. No suspended process
// exists while rules or UAC are pending. Closing this object never kills a
// launched application and never enables KILL_ON_JOB_CLOSE.
type Process struct {
	mu           sync.Mutex
	job, process windows.Handle
	identity     Identity
	ctx          context.Context
	program      Program
	started      bool
	closed       bool
	done         chan struct{}
	err          error
}

func Prepare(ctx context.Context, program Program) (*Process, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if windows.GetCurrentProcessToken().IsElevated() {
		return nil, errors.New("请以普通用户运行主程序；只有网络辅助服务需要管理员权限")
	}
	if err := ValidateProgram(program); err != nil {
		return nil, err
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, windowsError("创建软件进程组 CreateJobObject", err)
	}
	if err := ctx.Err(); err != nil {
		windows.CloseHandle(job)
		return nil, err
	}
	program.Args = append([]string(nil), program.Args...)
	return &Process{ctx: ctx, program: program, job: job, done: make(chan struct{})}, nil
}

func ValidateProgram(program Program) error {
	if !filepath.IsAbs(program.Executable) || !strings.EqualFold(filepath.Ext(program.Executable), ".exe") || strings.ContainsRune(program.Executable, 0) {
		return errors.New("请选择程序的完整 .exe 路径；快捷方式或脚本需先选择它们实际启动的程序")
	}
	info, err := os.Stat(program.Executable)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("程序文件不存在或不是普通文件")
	}
	if program.WorkDir != "" {
		if !filepath.IsAbs(program.WorkDir) || strings.ContainsRune(program.WorkDir, 0) {
			return errors.New("工作目录必须为完整路径")
		}
		dir, err := os.Stat(program.WorkDir)
		if err != nil || !dir.IsDir() {
			return errors.New("工作目录不存在或不是目录")
		}
	}
	if len(program.Args) > 256 {
		return errors.New("启动参数过多")
	}
	for _, arg := range program.Args {
		if strings.ContainsRune(arg, 0) || len(arg) > 8192 {
			return errors.New("启动参数无效或过长")
		}
	}
	return nil
}

func (p *Process) Identity() Identity    { p.mu.Lock(); defer p.mu.Unlock(); return p.identity }
func (p *Process) PID() int              { return int(p.Identity().PID) }
func (p *Process) Done() <-chan struct{} { return p.done }
func (p *Process) Err() error            { p.mu.Lock(); defer p.mu.Unlock(); return p.err }

// JobHandle is used only to duplicate JOB_OBJECT_QUERY access into the helper.
// The caller keeps this Process alive until the helper acknowledges attachment.
func (p *Process) JobHandle() uint64 { p.mu.Lock(); defer p.mu.Unlock(); return uint64(p.job) }

// Launch is called only after the helper acknowledges the empty job and rules.
// JOB_LIST makes assignment atomic with process creation (Windows 10+): even
// the application's first socket belongs to the already registered job.
func (p *Process) Launch() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return os.ErrClosed
	}
	if p.started {
		return errors.New("软件已经启动")
	}
	if err := p.ctx.Err(); err != nil {
		return err
	}
	attrs, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return windowsError("准备软件启动属性 InitializeProcThreadAttributeList", err)
	}
	defer attrs.Delete()
	const procThreadAttributeJobList = 0x0002000D
	if err = attrs.Update(procThreadAttributeJobList, unsafe.Pointer(&p.job), unsafe.Sizeof(p.job)); err != nil {
		return windowsError("设置软件进程组 UpdateProcThreadAttribute(JOB_LIST，需 Windows 10/11)", err)
	}
	exe, err := windows.UTF16PtrFromString(p.program.Executable)
	if err != nil {
		return err
	}
	line, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(append([]string{p.program.Executable}, p.program.Args...)))
	if err != nil {
		return err
	}
	workdir := p.program.WorkDir
	if workdir == "" {
		workdir = filepath.Dir(p.program.Executable)
	}
	dir, err := windows.UTF16PtrFromString(workdir)
	if err != nil {
		return err
	}
	si := windows.StartupInfoEx{ProcThreadAttributeList: attrs.List()}
	si.Cb = uint32(unsafe.Sizeof(si))
	var info windows.ProcessInformation
	if err = p.ctx.Err(); err != nil {
		return err
	}
	err = windows.CreateProcess(exe, line, nil, nil, false,
		windows.CREATE_UNICODE_ENVIRONMENT|windows.EXTENDED_STARTUPINFO_PRESENT,
		nil, dir, &si.StartupInfo, &info)
	runtime.KeepAlive(p)
	if err != nil {
		return windowsError("启动软件 CreateProcess", err)
	}
	p.started, p.process = true, info.Process
	_ = windows.CloseHandle(info.Thread)
	p.identity, err = processIdentity(info.Process, info.ProcessId)
	if err != nil {
		p.identity.PID = info.ProcessId
		p.err = fmt.Errorf("读取软件进程身份：%w", err)
		return p.err
	}
	go p.watch()
	return nil
}

func (p *Process) Contains(identity Identity) (bool, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, identity.PID)
	if err != nil {
		return false, err
	}
	defer windows.CloseHandle(h)
	actual, err := processIdentity(h, identity.PID)
	if err != nil || actual != identity {
		return false, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return false, os.ErrClosed
	}
	return inJob(h, p.job)
}

func inJob(process, job windows.Handle) (bool, error) {
	var result uint32
	ok, _, err := isProcessInJob.Call(uintptr(process), uintptr(job), uintptr(unsafe.Pointer(&result)))
	if ok == 0 {
		return false, err
	}
	return result != 0, nil
}

func processIdentity(handle windows.Handle, pid uint32) (Identity, error) {
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(handle, &created, &exited, &kernel, &user); err != nil {
		return Identity{}, windowsError("GetProcessTimes", err)
	}
	return Identity{PID: pid, Created: uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime)}, nil
}

type jobAccounting struct {
	TotalUser, TotalKernel, PeriodUser, PeriodKernel int64
	PageFaults, Total, Active, Terminated            uint32
}

func queryJob(job windows.Handle) (jobAccounting, error) {
	var accounting jobAccounting
	err := windows.QueryInformationJobObject(job, windows.JobObjectBasicAccountingInformation,
		uintptr(unsafe.Pointer(&accounting)), uint32(unsafe.Sizeof(accounting)), nil)
	return accounting, windowsError("QueryInformationJobObject", err)
}

// queryActive also counts children whose original parent has already exited.
func queryActive(job windows.Handle) (uint32, error) {
	accounting, err := queryJob(job)
	return accounting.Active, err
}

func requireEmptyJob(job windows.Handle) error {
	accounting, err := queryJob(job)
	if err != nil {
		return err
	}
	if accounting.Total != 0 || accounting.Active != 0 {
		return errors.New("只能接管尚未启动软件的新进程组")
	}
	return nil
}

func (p *Process) watch() {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-p.done:
			return
		case <-ticker.C:
			p.mu.Lock()
			if p.closed {
				p.mu.Unlock()
				return
			}
			active, err := queryActive(p.job)
			if err != nil {
				p.err = fmt.Errorf("读取软件进程组：%w", err)
			}
			p.mu.Unlock()
			if err != nil || active == 0 {
				_ = p.Close()
				return
			}
		}
	}
}

func (p *Process) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return p.err
	}
	p.closed = true
	for _, handle := range []windows.Handle{p.process, p.job} {
		if handle != 0 {
			p.err = errors.Join(p.err, windows.CloseHandle(handle))
		}
	}
	p.process, p.job = 0, 0
	close(p.done)
	return p.err
}
