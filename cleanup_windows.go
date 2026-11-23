//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ehzyil/connect-hub/internal/sangforclean"
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
		candidate := filepath.Join(dir, "connect-hub-cleanup.exe")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	// 尝试当前工作目录或环境变量
	if _, err := os.Stat("connect-hub-cleanup.exe"); err == nil {
		abs, _ := filepath.Abs("connect-hub-cleanup.exe")
		return abs
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
	a.cleanup.status = cleanupStatusScanning
	a.cleanup.err = ""
	a.cleanup.message = "正在扫描残留组件..."
	a.cleanup.mu.Unlock()
	a.invalidate()

	go func() {
		// 优先直接调用 internal 库扫描（极速、无需依赖外部 exe 文件存在）
		plan, err := sangforclean.Scan(sangforclean.ScanOptions{})

		a.cleanup.mu.Lock()
		defer a.cleanup.mu.Unlock()

		if err != nil {
			a.cleanup.status = cleanupStatusFailed
			a.cleanup.err = fmt.Sprintf("扫描失败: %v", err)
			a.invalidate()
			return
		}

		a.cleanup.plan = plan
		a.cleanup.selectedMap = make(map[string]bool)
		for _, f := range plan.Findings {
			a.cleanup.selectedMap[f.ID] = f.Selected
		}

		// 刷新可用备份
		a.cleanup.backups, _ = sangforclean.ListBackups("")

		a.cleanup.status = cleanupStatusReady
		a.cleanup.message = fmt.Sprintf("检测到 %d 项残留组件", len(plan.Findings))
		a.invalidate()
	}()
}

func (a *app) runCleanupApply() {
	a.cleanup.mu.Lock()
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

	// 更新 plan 中用户的勾选状态
	for i := range a.cleanup.plan.Findings {
		id := a.cleanup.plan.Findings[i].ID
		a.cleanup.plan.Findings[i].Selected = a.cleanup.selectedMap[id]
	}

	tmpDir := os.TempDir()
	planPath := filepath.Join(tmpDir, "connect-hub-cleanup-plan.json")
	reportPath := filepath.Join(tmpDir, "connect-hub-cleanup-report.jsonl")
	_ = os.Remove(reportPath)

	_ = sangforclean.SavePlanToFile(planPath, a.cleanup.plan)
	a.cleanup.planPath = planPath
	a.cleanup.reportPath = reportPath

	exePath := a.findCleanupExe()
	a.cleanup.mu.Unlock()
	a.invalidate()

	go func() {
		// 如果找到独立 exe，使用 ShellExecuteEx 提权执行
		if exePath != "" {
			args := fmt.Sprintf("--apply %s --report %s --yes --hide", planPath, reportPath)
			stopPoll := make(chan struct{})
			go a.pollReportLoop(reportPath, stopPoll)

			exitCode, err := sangforclean.RunElevatedAndWait(exePath, args, true)
			close(stopPoll)
			a.readFinalReport(reportPath, exitCode, err)
		} else {
			// 开发环境下若 exe 尚未打包，走内联 apply
			rw, _ := sangforclean.NewReportWriter(reportPath)
			code, err := sangforclean.Apply(sangforclean.ApplyOptions{
				Plan:       a.cleanup.plan,
				ReportPath: reportPath,
			})
			if rw != nil {
				_ = rw.Close()
			}
			a.readFinalReport(reportPath, code, err)
		}
	}()
}

func (a *app) runCleanupRestore(manifestPath string) {
	a.cleanup.mu.Lock()
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
			args := fmt.Sprintf("--restore %s --report %s --hide", manifestPath, reportPath)
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
	defer a.cleanup.mu.Unlock()

	// 统计结果
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
	} else if exitCode == 3 {
		a.cleanup.status = cleanupStatusDone
		a.cleanup.message = "清理完成，部分驱动/文件需重启生效"
	} else if exitCode == 4 {
		a.cleanup.status = cleanupStatusReady
		a.cleanup.err = "用户取消了管理员 UAC 授权"
	} else {
		a.cleanup.status = cleanupStatusFailed
		a.cleanup.err = fmt.Sprintf("执行出现错误 (退出码: %d, 错误: %v)", exitCode, err)
	}

	// 刷新备份列表
	a.cleanup.backups, _ = sangforclean.ListBackups("")
	a.invalidate()
}

func (a *app) launchOfficialUninstaller(uninstStr string) {
	parts := strings.Fields(uninstStr)
	if len(parts) == 0 {
		return
	}
	exe := strings.Trim(parts[0], `"`)
	args := parts[1:]

	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: false}
	_ = cmd.Start()
}
