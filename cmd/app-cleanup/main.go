//go:build windows

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"github.com/ehzyil/connect-hub/internal/sangforclean"
	"golang.org/x/sys/windows"
)

const ProtocolVersion = 2

var (
	modkernel32          = windows.NewLazySystemDLL("kernel32.dll")
	moduser32            = windows.NewLazySystemDLL("user32.dll")
	procGetConsoleWindow = modkernel32.NewProc("GetConsoleWindow")
	procShowWindow       = moduser32.NewProc("ShowWindow")
)

const SW_HIDE = 0

func hideCurrentConsole() {
	hwnd, _, _ := procGetConsoleWindow.Call()
	if hwnd != 0 {
		procShowWindow.Call(hwnd, SW_HIDE)
	}
}

func debugLog(format string, args ...interface{}) {
	logPath := filepath.Join(os.TempDir(), "connect-hub-cleanup.log")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	msg := fmt.Sprintf(format, args...)
	_, _ = fmt.Fprintf(f, "[%s] [pid=%d, elevated=%v] %s\n", time.Now().Format("2006-01-02 15:04:05.000"), os.Getpid(), sangforclean.IsElevated(), msg)
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			debugLog("FATAL PANIC: %v", r)
			msg := fmt.Sprintf("程序发生异常崩溃: %v\n详情见日志: %s", r, filepath.Join(os.TempDir(), "connect-hub-cleanup.log"))
			title, _ := windows.UTF16PtrFromString("Connect Hub 清理工具异常")
			text, _ := windows.UTF16PtrFromString(msg)
			windows.MessageBox(0, text, title, windows.MB_OK|windows.MB_ICONERROR)
		}
	}()

	debugLog("main started with args: %v", os.Args)

	scanFlag := flag.Bool("scan", false, "只读扫描，产出 plan")
	outFlag := flag.String("out", "", "plan 输出路径（缺省写 stdout）")
	applyFlag := flag.String("apply", "", "执行 plan.json 文件")
	restoreFlag := flag.String("restore", "", "从 backup-manifest.json 还原")
	listBackupsFlag := flag.Bool("list-backups", false, "列出历史备份点")
	backupDirFlag := flag.String("backup-dir", "", "指定备份存储根目录")
	reportFlag := flag.String("report", "", "执行进度报告 JSONL 输出路径")
	jsonFlag := flag.Bool("json", false, "输出机器可读 JSON")
	noElevateFlag := flag.Bool("no-elevate", false, "禁止自提权")
	hideFlag := flag.Bool("hide", false, "提权时隐藏控制台窗口")
	onlyFlag := flag.String("only", "", "逗号分隔的条目 ID 列表（只执行指定项）")
	skipFlag := flag.String("skip", "", "逗号分隔的条目 ID 列表（跳过指定项）")
	yesFlag := flag.Bool("yes", false, "跳过交互确认")
	protoVerFlag := flag.Bool("protocol-version", false, "打印清理器协议版本")
	_ = flag.Bool("interactive-run", false, "交互模式提权标记")

	flag.Parse()

	if *protoVerFlag {
		fmt.Println(ProtocolVersion)
		os.Exit(0)
	}

	if *listBackupsFlag {
		debugLog("executing listBackups")
		backups, err := sangforclean.ListBackups(*backupDirFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "列出备份失败: %v\n", err)
			os.Exit(1)
		}
		if *jsonFlag {
			data, _ := json.MarshalIndent(backups, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("找到 %d 个备份点:\n", len(backups))
			for _, b := range backups {
				fmt.Printf(" - ID: %s (时间: %s, 注册表: %d, 文件: %d, 证书: %d)\n",
					b.BackupID, b.CreatedAt.Format("2006-01-02 15:04:05"),
					len(b.Registry), len(b.Files), len(b.Certificates))
			}
		}
		os.Exit(0)
	}

	// 还原模式
	if *restoreFlag != "" {
		debugLog("executing restore: %s", *restoreFlag)
		if !sangforclean.IsElevated() {
			if *noElevateFlag {
				fmt.Fprintln(os.Stderr, "还原需要管理员权限且禁止自提权")
				os.Exit(4)
			}
			exe, _ := os.Executable()
			code, err := sangforclean.RunElevatedAndWait(exe, windows.ComposeCommandLine(os.Args[1:]), *hideFlag)
			if err != nil {
				fmt.Fprintf(os.Stderr, "提权启动失败: %v\n", err)
			}
			os.Exit(code)
		}

		var rw *sangforclean.ReportWriter
		if *reportFlag != "" {
			var err error
			rw, err = sangforclean.NewReportWriter(*reportFlag)
			if err != nil {
				fmt.Fprintf(os.Stderr, "创建报告失败: %v\n", err)
				os.Exit(2)
			}
			defer rw.Close()
		}

		fmt.Println("正在从备份清单执行还原...")
		if err := sangforclean.RestoreBackup(*restoreFlag, rw); err != nil {
			fmt.Fprintf(os.Stderr, "还原失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("还原执行完成！")
		os.Exit(0)
	}

	// 扫描模式
	if *scanFlag {
		debugLog("executing scan")
		plan, err := sangforclean.Scan(sangforclean.ScanOptions{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "扫描失败: %v\n", err)
			os.Exit(1)
		}

		if *outFlag != "" {
			if err := sangforclean.SavePlanToFile(*outFlag, plan); err != nil {
				fmt.Fprintf(os.Stderr, "保存 plan 失败: %v\n", err)
				os.Exit(2)
			}
		} else {
			data, _ := json.MarshalIndent(plan, "", "  ")
			fmt.Println(string(data))
		}
		os.Exit(0)
	}

	// Apply 模式
	if *applyFlag != "" {
		debugLog("executing apply: %s", *applyFlag)
		if !sangforclean.IsElevated() {
			if *noElevateFlag {
				fmt.Fprintln(os.Stderr, "执行清理需要管理员权限且禁止自提权")
				os.Exit(4)
			}
			exe, _ := os.Executable()
			code, err := sangforclean.RunElevatedAndWait(exe, windows.ComposeCommandLine(os.Args[1:]), *hideFlag)
			if err != nil {
				fmt.Fprintf(os.Stderr, "提权失败: %v\n", err)
			}
			os.Exit(code)
		}

		data, err := os.ReadFile(*applyFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "读取 plan 失败: %v\n", err)
			os.Exit(2)
		}

		var plan sangforclean.Plan
		if err := json.Unmarshal(data, &plan); err != nil {
			fmt.Fprintf(os.Stderr, "解析 plan 失败: %v\n", err)
			os.Exit(2)
		}

		var onlyIDs []string
		if *onlyFlag != "" {
			onlyIDs = strings.Split(*onlyFlag, ",")
		}
		var skipIDs []string
		if *skipFlag != "" {
			skipIDs = strings.Split(*skipFlag, ",")
		}

		code, err := sangforclean.Apply(sangforclean.ApplyOptions{
			Plan:          &plan,
			ReportPath:    *reportFlag,
			OnlyIDs:       onlyIDs,
			SkipIDs:       skipIDs,
			BackupRootDir: *backupDirFlag,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "执行清理遇到错误: %v\n", err)
		}
		os.Exit(code)
	}

	// 无参数：进入终端交互模式
	runInteractiveMode(*backupDirFlag, *yesFlag)
}

func runInteractiveMode(backupDir string, skipConfirm bool) {
	// 如果未提权，隐藏当前未提权的控制台，直接交接给提权后的新控制台，彻底消除“双窗口”
	if !sangforclean.IsElevated() {
		debugLog("not elevated, hiding current console and spawning elevated instance")
		hideCurrentConsole()

		exe, _ := os.Executable()
		// 启动提权进程后立即退出自身，由提权后的全新控制台完全接管交互
		if err := spawnElevatedAndDetach(exe, "--interactive-run"); err != nil {
			debugLog("spawnElevatedAndDetach failed: %v", err)
			title, _ := windows.UTF16PtrFromString("权限提示")
			text, _ := windows.UTF16PtrFromString("需要管理员权限才能扫描和清理系统深信服残留组件。")
			windows.MessageBox(0, text, title, windows.MB_OK|windows.MB_ICONWARNING)
			os.Exit(4)
		}
		// 提权成功发起后，普通权限的父窗口直接退出，屏幕上只留下一个提权控制台
		os.Exit(0)
	}

	debugLog("in elevated interactive mode")
	fmt.Println("====================================================")
	fmt.Println("   Connect Hub - aTrust / EasyConnect 残留清理工具   ")
	fmt.Println("====================================================")
	fmt.Println("正在扫描残留组件...")

	plan, err := sangforclean.Scan(sangforclean.ScanOptions{})
	if err != nil {
		debugLog("scan failed in interactive mode: %v", err)
		fmt.Printf("扫描失败: %v\n", err)
		pauseAndExit(1)
	}

	debugLog("scan success: %d installed, %d findings", len(plan.Installed), len(plan.Findings))

	if len(plan.Installed) > 0 {
		fmt.Println("\n【检测到官方客户端】")
		for _, inst := range plan.Installed {
			fmt.Printf(" - %s (卸载入口: %s)\n", inst.Name, inst.UninstallString)
		}
		fmt.Println("建议先运行上述官方卸载器卸载主程序后再清理残留。")
	}

	if len(plan.Findings) == 0 {
		fmt.Println("\n🎉 未检测到任何 Sangfor / aTrust / EasyConnect 残留！系统非常干净。")
		pauseAndExit(0)
	}

	fmt.Printf("\n检测到 %d 项残留组件:\n", len(plan.Findings))
	for i, f := range plan.Findings {
		riskTag := "[建议清理]"
		if f.Risk == sangforclean.RiskDeep {
			riskTag = "[深度项·默认不勾]"
		}
		fmt.Printf(" %2d. %-15s %s (%s)\n", i+1, riskTag, f.Title, f.Detail)
	}

	if !skipConfirm {
		fmt.Print("\n是否立即执行全量备份并清理上述建议项？[y/N]: ")
		input := readConsoleLine()
		debugLog("user confirmation input: %q", input)
		input = strings.TrimSpace(strings.ToLower(input))
		if input != "y" && input != "yes" {
			fmt.Println("操作已取消。")
			pauseAndExit(0)
		}
	}

	fmt.Println("\n正在进行清理前全量镜像备份...")
	code, err := sangforclean.Apply(sangforclean.ApplyOptions{
		Plan:          plan,
		BackupRootDir: backupDir,
	})
	if err != nil {
		debugLog("apply failed: %v", err)
		fmt.Printf("清理执行遇到错误: %v\n", err)
	} else if code == 0 {
		fmt.Println("\n✅ 清理完成！全部建议项已成功清除。")
	} else if code == 3 {
		fmt.Println("\n⚠️ 清理完成，部分驱动与文件已登记在系统重启后删除，建议重启电脑生效。")
	} else {
		fmt.Printf("\n⚠️ 清理完成，部分项目未能成功删除 (退出码: %d)。\n", code)
	}

	pauseAndExit(code)
}

func spawnElevatedAndDetach(exePath string, args string) error {
	verb, err := windows.UTF16PtrFromString("runas")
	if err != nil {
		return err
	}
	file, err := windows.UTF16PtrFromString(exePath)
	if err != nil {
		return err
	}
	params, err := windows.UTF16PtrFromString(args)
	if err != nil {
		return err
	}
	dir, err := windows.UTF16PtrFromString(filepath.Dir(exePath))
	if err != nil {
		return err
	}

	var sei sangforclean.SHELLEXECUTEINFOW
	sei.CbSize = uint32(unsafe.Sizeof(sei))
	sei.LpVerb = verb
	sei.LpFile = file
	sei.LpParameters = params
	sei.LpDirectory = dir
	sei.NShow = 1 // SW_SHOWNORMAL 正常显示新提权控制台

	procShellExecuteExW := windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteExW")
	ret, _, callErr := procShellExecuteExW.Call(uintptr(unsafe.Pointer(&sei)))
	if ret == 0 {
		return fmt.Errorf("UAC 提权被拒绝或取消: %v", callErr)
	}
	return nil
}

func readConsoleLine() string {
	conin, err := os.Open("CONIN$")
	if err == nil {
		defer conin.Close()
		scanner := bufio.NewScanner(conin)
		if scanner.Scan() {
			return scanner.Text()
		}
	}

	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		return scanner.Text()
	}
	return ""
}

func pauseAndExit(code int) {
	fmt.Print("\n按 Enter 键退出...")
	_ = readConsoleLine()
	debugLog("pausing complete, exiting with %d", code)
	os.Exit(code)
}
