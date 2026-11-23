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

		a.cleanup.backups, _ = sangforclean.ListBackups("")
		a.cleanup.status = cleanupStatusReady
		a.cleanup.message = fmt.Sprintf("检测到 %d 项残留组件", len(plan.Findings))
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
	defer a.cleanup.mu.Unlock()

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

	a.cleanup.backups, _ = sangforclean.ListBackups("")
	a.invalidate()
}

func (a *app) launchOfficialUninstaller(uninstStr string) {
	uninstStr = strings.TrimSpace(uninstStr)
	if uninstStr == "" {
		return
	}

	var exe string
	var args []string

	// 解析带引号包裹路径的命令行
	if strings.HasPrefix(uninstStr, `"`) {
		endIdx := strings.Index(uninstStr[1:], `"`)
		if endIdx != -1 {
			exe = uninstStr[1 : endIdx+1]
			rest := strings.TrimSpace(uninstStr[endIdx+2:])
			if rest != "" {
				args = strings.Fields(rest)
			}
		} else {
			exe = strings.Trim(uninstStr, `"`)
		}
	} else {
		parts := strings.Fields(uninstStr)
		if len(parts) > 0 {
			exe = parts[0]
			args = parts[1:]
		}
	}

	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: false}
	if err := cmd.Start(); err == nil {
		// 释放进程句柄，避免长期泄漏
		if cmd.Process != nil {
			_ = cmd.Process.Release()
		}
	}
}
