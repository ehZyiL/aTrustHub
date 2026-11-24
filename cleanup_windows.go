//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ehzyil/connect-hub/internal/sangforclean"
	"golang.org/x/sys/windows"
)

func supportsCleanup() bool {
	return true
}

type cleanupStatus string

const (
	cleanupStatusIdle      cleanupStatus = "idle"
	cleanupStatusScanning  cleanupStatus = "scanning"
	cleanupStatusReady     cleanupStatus = "ready"
	cleanupStatusApplying  cleanupStatus = "applying"
	cleanupStatusRestoring cleanupStatus = "restoring"
	cleanupStatusDone      cleanupStatus = "done"
	cleanupStatusFailed    cleanupStatus = "failed"
)

type cleanupState struct {
	mu           sync.RWMutex
	status       cleanupStatus
	plan         *sangforclean.Plan
	selectedMap  map[string]bool
	reportPath   string
	planPath     string
	events       []sangforclean.ReportEvent
	message      string
	lastBackupID string
	err          string
	totalItems   int
	okItems      int
	failedItems  int
	rebootItems  int
	backups      []sangforclean.BackupManifest
}

func (a *app) findCleanupExe() string {
	exe, err := os.Executable()
	if err == nil {
		dir := filepath.Dir(exe)
		for _, candidate := range []string{
			filepath.Join(dir, "core", "connect-hub-cleanup.exe"),
			filepath.Join(dir, "connect-hub-cleanup.exe"),
		} {
			if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
				return candidate
			}
		}
	}
	for _, candidate := range []string{
		filepath.Join("core", "connect-hub-cleanup.exe"),
		"connect-hub-cleanup.exe",
	} {
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			abs, _ := filepath.Abs(candidate)
			return abs
		}
	}
	return ""
}

func (a *app) initCleanupState() {
	a.cleanup.mu.Lock()
	defer a.cleanup.mu.Unlock()

	if a.cleanup.selectedMap == nil {
		a.cleanup.selectedMap = make(map[string]bool)
	}
	if a.cleanup.status == "" {
		a.cleanup.status = cleanupStatusIdle
	}
}

func (a *app) runCleanupScan() {
	a.cleanup.mu.Lock()
	if a.cleanup.status == cleanupStatusScanning || a.cleanup.status == cleanupStatusApplying || a.cleanup.status == cleanupStatusRestoring {
		a.cleanup.mu.Unlock()
		return
	}
	a.cleanup.status = cleanupStatusScanning
	a.cleanup.err = ""
	a.cleanup.message = "正在扫描残留组件..."
	a.cleanup.mu.Unlock()
	a.invalidate()

	go func() {
		plan, err := sangforclean.Scan(sangforclean.ScanOptions{})

		a.cleanup.mu.Lock()
		if err != nil {
			a.cleanup.status = cleanupStatusFailed
			a.cleanup.err = fmt.Sprintf("扫描失败: %v", err)
			a.cleanup.mu.Unlock()
			a.invalidate()
			return
		}

		a.cleanup.plan = plan
		a.cleanup.selectedMap = make(map[string]bool)
		for _, f := range plan.Findings {
			a.cleanup.selectedMap[f.ID] = f.Selected
		}

		a.cleanup.backups, _ = sangforclean.ListBackups("")
		a.cleanup.status = cleanupStatusReady
		a.cleanup.message = fmt.Sprintf("检测到 %d 项残留组件", len(plan.Findings))
		a.cleanup.mu.Unlock()
		a.invalidate()
	}()
}

func (a *app) runCleanupApply() {
	a.cleanup.mu.Lock()
	if a.cleanup.status == cleanupStatusApplying || a.cleanup.status == cleanupStatusScanning || a.cleanup.status == cleanupStatusRestoring {
		a.cleanup.mu.Unlock()
		return
	}
	if a.cleanup.plan == nil {
		a.cleanup.mu.Unlock()
		return
	}

	a.cleanup.status = cleanupStatusApplying
	a.cleanup.events = make([]sangforclean.ReportEvent, 0)
	a.cleanup.message = "正在提权执行备份与清理..."
	a.cleanup.okItems = 0
	a.cleanup.failedItems = 0
	a.cleanup.rebootItems = 0

	// 深拷贝 Plan，杜绝后台复核扩容与 UI 遍历发生并发竞争
	planCopy := *a.cleanup.plan
	planCopy.Findings = make([]sangforclean.Finding, len(a.cleanup.plan.Findings))
	for i := range a.cleanup.plan.Findings {
		planCopy.Findings[i] = a.cleanup.plan.Findings[i]
		id := planCopy.Findings[i].ID
		planCopy.Findings[i].Selected = a.cleanup.selectedMap[id]
	}

	tmpDir := os.TempDir()
	planPath := filepath.Join(tmpDir, "connect-hub-cleanup-plan.json")
	reportPath := filepath.Join(tmpDir, "connect-hub-cleanup-report.jsonl")
	_ = os.Remove(reportPath)

	_ = sangforclean.SavePlanToFile(planPath, &planCopy)
	a.cleanup.planPath = planPath
	a.cleanup.reportPath = reportPath

	exePath := a.findCleanupExe()
	a.cleanup.mu.Unlock()
	a.invalidate()

	go func() {
		if exePath != "" {
			// 路径加引号，防止带空格的路径解析截断
			args := fmt.Sprintf(`--apply "%s" --report "%s" --yes --hide`, planPath, reportPath)
			stopPoll := make(chan struct{})
			go a.pollReportLoop(reportPath, stopPoll)

			exitCode, err := sangforclean.RunElevatedAndWait(exePath, args, true)
			close(stopPoll)
			a.readFinalReport(reportPath, exitCode, err)
		} else {
			code, err := sangforclean.Apply(sangforclean.ApplyOptions{
				Plan:       &planCopy,
				ReportPath: reportPath,
			})
			a.readFinalReport(reportPath, code, err)
		}
	}()
}

func (a *app) runCleanupRestore(manifestPath string) {
	a.cleanup.mu.Lock()
	if a.cleanup.status == cleanupStatusApplying || a.cleanup.status == cleanupStatusRestoring {
		a.cleanup.mu.Unlock()
		return
	}
	a.cleanup.status = cleanupStatusRestoring
	a.cleanup.events = make([]sangforclean.ReportEvent, 0)
	a.cleanup.message = "正在执行一键还原..."

	tmpDir := os.TempDir()
	reportPath := filepath.Join(tmpDir, "connect-hub-restore-report.jsonl")
	_ = os.Remove(reportPath)
	a.cleanup.reportPath = reportPath

	exePath := a.findCleanupExe()
	a.cleanup.mu.Unlock()
	a.invalidate()

	go func() {
		if exePath != "" {
			args := fmt.Sprintf(`--restore "%s" --report "%s" --hide`, manifestPath, reportPath)
			exitCode, err := sangforclean.RunElevatedAndWait(exePath, args, true)
			a.readFinalReport(reportPath, exitCode, err)
		} else {
			rw, _ := sangforclean.NewReportWriter(reportPath)
			err := sangforclean.RestoreBackup(manifestPath, rw)
			if rw != nil {
				_ = rw.Close()
			}
			exitCode := 0
			if err != nil {
				exitCode = 1
			}
			a.readFinalReport(reportPath, exitCode, err)
		}
	}()
}

func (a *app) pollReportLoop(reportPath string, stop <-chan struct{}) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			a.updateEventsFromFile(reportPath)
		}
	}
}

func (a *app) updateEventsFromFile(reportPath string) {
	data, err := os.ReadFile(reportPath)
	if err != nil || len(data) == 0 {
		return
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var events []sangforclean.ReportEvent
	for _, l := range lines {
		var ev sangforclean.ReportEvent
		if err := json.Unmarshal([]byte(l), &ev); err == nil {
			events = append(events, ev)
		}
	}

	a.cleanup.mu.Lock()
	a.cleanup.events = events
	a.cleanup.mu.Unlock()
	a.invalidate()
}

func (a *app) readFinalReport(reportPath string, exitCode int, err error) {
	a.updateEventsFromFile(reportPath)

	a.cleanup.mu.Lock()
	ok := 0
	failed := 0
	reboot := 0
	for _, ev := range a.cleanup.events {
		switch ev.Status {
		case sangforclean.StatusOk:
			ok++
		case sangforclean.StatusFailed:
			failed++
		case sangforclean.StatusReboot:
			reboot++
		}
		if ev.BackupID != "" {
			a.cleanup.lastBackupID = ev.BackupID
		}
	}

	a.cleanup.okItems = ok
	a.cleanup.failedItems = failed
	a.cleanup.rebootItems = reboot

	if exitCode == 0 {
		a.cleanup.status = cleanupStatusDone
		a.cleanup.message = "清理已成功完成！"
		a.cleanup.err = ""
	} else if exitCode == 3 {
		a.cleanup.status = cleanupStatusDone
		a.cleanup.message = "清理完成，部分驱动/文件需重启生效"
		a.cleanup.err = ""
	} else if exitCode == 4 {
		a.cleanup.status = cleanupStatusReady
		a.cleanup.err = "用户取消了管理员 UAC 授权"
	} else {
		a.cleanup.status = cleanupStatusFailed
		if err != nil {
			a.cleanup.err = fmt.Sprintf("执行出现错误 (退出码: %d, %v)", exitCode, err)
		} else {
			a.cleanup.err = fmt.Sprintf("部分项目未能成功清除 (退出码: %d)", exitCode)
		}
	}

	a.cleanup.backups, _ = sangforclean.ListBackups("")
	a.cleanup.mu.Unlock()
	a.invalidate()

	// 自动异步重新扫描系统真实状态，即时刷新界面上的残留项列表，无需用户手动重启客户端
	go func() {
		freshPlan, freshErr := sangforclean.Scan(sangforclean.ScanOptions{})
		if freshErr == nil && freshPlan != nil {
			a.cleanup.mu.Lock()
			a.cleanup.plan = freshPlan
			a.cleanup.selectedMap = make(map[string]bool)
			for _, f := range freshPlan.Findings {
				a.cleanup.selectedMap[f.ID] = f.Selected
			}
			a.cleanup.mu.Unlock()
			a.invalidate()
		}
	}()
}

func (a *app) launchOfficialUninstaller(uninstStr string) {
	exe, args := sangforclean.SplitUninstallString(uninstStr)
	if exe == "" {
		a.cleanup.mu.Lock()
		a.cleanup.err = "未找到有效的卸载程序路径"
		a.cleanup.mu.Unlock()
		a.invalidate()
		return
	}

	// 检查卸载文件是否存在（若已被手动删除则友好提示）
	if _, statErr := os.Stat(exe); statErr != nil {
		a.cleanup.mu.Lock()
		a.cleanup.err = fmt.Sprintf("卸载程序不存在（%s），可直接在下方勾选残留进行清理", filepath.Base(exe))
		a.cleanup.message = ""
		a.cleanup.mu.Unlock()
		a.invalidate()
		return
	}

	verbRunAs, _ := windows.UTF16PtrFromString("runas")
	verbOpen, _ := windows.UTF16PtrFromString("open")
	filePtr, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		a.cleanup.mu.Lock()
		a.cleanup.err = fmt.Sprintf("路径编码失败: %v", err)
		a.cleanup.mu.Unlock()
		a.invalidate()
		return
	}

	var paramsPtr *uint16
	if args != "" {
		paramsPtr, _ = windows.UTF16PtrFromString(args)
	}
	dirPtr, _ := windows.UTF16PtrFromString(filepath.Dir(exe))

	// 优先以管理员权限 (runas) 拉起卸载向导，弹出系统 UAC 对话框
	execErr := windows.ShellExecute(0, verbRunAs, filePtr, paramsPtr, dirPtr, windows.SW_SHOWNORMAL)
	if execErr != nil {
		// 若 runas 失败，回退尝试普通 open
		execErr = windows.ShellExecute(0, verbOpen, filePtr, paramsPtr, dirPtr, windows.SW_SHOWNORMAL)
	}

	a.cleanup.mu.Lock()
	if execErr != nil {
		a.cleanup.err = fmt.Sprintf("启动官方卸载程序失败: %v", execErr)
		a.cleanup.message = ""
	} else {
		a.cleanup.message = fmt.Sprintf("已启动官方卸载向导: %s（请按系统弹窗提示操作）", filepath.Base(exe))
		a.cleanup.err = ""
	}
	a.cleanup.mu.Unlock()
	a.invalidate()
}
