//go:build windows

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/ehzyil/connect-hub/internal/sangforclean"
)

const ProtocolVersion = 2

func main() {
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

	flag.Parse()

	if *protoVerFlag {
		fmt.Println(ProtocolVersion)
		os.Exit(0)
	}

	if *listBackupsFlag {
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
		if !sangforclean.IsElevated() {
			if *noElevateFlag {
				fmt.Fprintln(os.Stderr, "还原需要管理员权限且禁止自提权")
				os.Exit(4)
			}
			// 自提权并等待
			exe, _ := os.Executable()
			code, err := sangforclean.RunElevatedAndWait(exe, strings.Join(os.Args[1:], " "), *hideFlag)
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
		if !sangforclean.IsElevated() {
			if *noElevateFlag {
				fmt.Fprintln(os.Stderr, "执行清理需要管理员权限且禁止自提权")
				os.Exit(4)
			}
			// 自提权
			exe, _ := os.Executable()
			code, err := sangforclean.RunElevatedAndWait(exe, strings.Join(os.Args[1:], " "), *hideFlag)
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
	if !sangforclean.IsElevated() {
		fmt.Println("正在请求管理员权限以进行深信服组件清理...")
		exe, _ := os.Executable()
		code, err := sangforclean.RunElevatedAndWait(exe, "--interactive-run", false)
		if err != nil {
			fmt.Printf("提权未完成: %v\n", err)
		}
		os.Exit(code)
	}

	fmt.Println("====================================================")
	fmt.Println("   Connect Hub - aTrust / EasyConnect 残留清理工具   ")
	fmt.Println("====================================================")
	fmt.Println("正在扫描残留组件...")

	plan, err := sangforclean.Scan(sangforclean.ScanOptions{})
	if err != nil {
		fmt.Printf("扫描失败: %v\n", err)
		pauseAndExit(1)
	}

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
		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
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

func pauseAndExit(code int) {
	fmt.Print("\n按 Enter 键退出...")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	os.Exit(code)
}
