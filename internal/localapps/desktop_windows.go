package localapps

import (
	"errors"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"github.com/qy/easyconnect/internal/model"
	"github.com/qy/easyconnect/internal/wincapture"
	"golang.org/x/sys/windows"
)

// ReadWindowsProgram resolves the Start-menu entry enumerated by MyGo.
// Inspect shell metadata without ShellExecute: Shell activation could hand
// work to an existing process outside the job or run the application early.
func ReadWindowsProgram(path string) (model.LocalApp, error) {
	if filepath.IsAbs(path) && strings.EqualFold(filepath.Ext(path), ".exe") {
		p := model.LocalApp{Executable: path}
		return p, wincapture.ValidateProgram(wincapture.Program{Executable: path})
	}
	const prefix = `shell:AppsFolder\`
	if !strings.HasPrefix(path, prefix) || len(path) == len(prefix) || strings.ContainsRune(path, 0) {
		return model.LocalApp{}, errors.New("请选择实际 .exe 文件，或从已安装软件列表选择桌面程序")
	}
	type result struct {
		p   model.LocalApp
		err error
	}
	output := make(chan result, 1)
	// COM gets its own apartment; never change the GUI thread's COM mode.
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if err := ole.CoInitializeEx(0, ole.COINIT_APARTMENTTHREADED); err != nil {
			if code, ok := err.(*ole.OleError); !ok || code.Code() != 1 {
				output <- result{err: err}
				return
			}
		}
		defer ole.CoUninitialize()
		p, err := resolveShellProgram(strings.TrimPrefix(path, prefix))
		output <- result{p, err}
	}()
	r := <-output
	return r.p, r.err
}

func resolveShellProgram(id string) (model.LocalApp, error) {
	failure := errors.New("此开始菜单项目未提供可直接启动的 .exe，请使用浏览按钮选择程序文件；商店应用暂不支持")
	unknown, err := oleutil.CreateObject("Shell.Application")
	if err != nil {
		return model.LocalApp{}, failure
	}
	defer unknown.Release()
	shell, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return model.LocalApp{}, failure
	}
	defer shell.Release()
	folderValue, err := oleutil.CallMethod(shell, "NameSpace", "shell:AppsFolder")
	if err != nil {
		return model.LocalApp{}, failure
	}
	defer folderValue.Clear()
	folder := folderValue.ToIDispatch()
	if folder == nil {
		return model.LocalApp{}, failure
	}
	itemValue, err := oleutil.CallMethod(folder, "ParseName", id)
	if err != nil {
		return model.LocalApp{}, failure
	}
	defer itemValue.Clear()
	item := itemValue.ToIDispatch()
	if item == nil {
		return model.LocalApp{}, failure
	}
	property := func(name string) string {
		v, err := oleutil.CallMethod(item, "ExtendedProperty", name)
		if err != nil {
			return ""
		}
		defer v.Clear()
		return v.ToString()
	}
	p := model.LocalApp{Executable: property("System.Link.TargetParsingPath"), WorkDir: property("System.Link.WorkingDirectory")}
	args := property("System.Link.Arguments")
	// Some desktop items expose the executable in the relaunch command.
	// Parse with the Windows command-line API; never pass a shell command.
	if p.Executable == "" {
		command := property("System.AppUserModel.RelaunchCommand")
		argv, err := windows.DecomposeCommandLine(command)
		if err != nil || len(argv) == 0 {
			return model.LocalApp{}, failure
		}
		p.Executable, p.Args = argv[0], argv[1:]
	} else if args != "" {
		argv, err := windows.DecomposeCommandLine(`placeholder.exe ` + args)
		if err != nil || len(argv) == 0 {
			return model.LocalApp{}, failure
		}
		p.Args = argv[1:]
	}
	if err := wincapture.ValidateProgram(wincapture.Program{Executable: p.Executable, Args: p.Args, WorkDir: p.WorkDir}); err != nil {
		return model.LocalApp{}, failure
	}
	return p, nil
}
