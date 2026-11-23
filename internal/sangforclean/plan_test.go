package sangforclean

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPlanSerialization(t *testing.T) {
	plan := &Plan{
		Version:   2,
		ScannedAt: time.Now(),
		Elevated:  false,
		Installed: []InstalledApp{
			{
				Name:            "EasyConnect",
				UninstallString: `C:\Program Files (x86)\Sangfor\SSL\EasyConnect\Uninstall.exe`,
				Hive:            "HKLM",
				Key:             `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\EasyConnect`,
			},
		},
		Findings: []Finding{
			{
				ID:       "svc:SangforSP",
				Group:    "service",
				Family:   "ec",
				Title:    "SangforSP",
				Detail:   "服务 · 运行中",
				Risk:     RiskNormal,
				Action:   ActionDeleteService,
				Params:   map[string]interface{}{"name": "SangforSP"},
				Selected: true,
			},
			{
				ID:       "drv:WinDivert",
				Group:    "driver",
				Title:    "WinDivert",
				Detail:   "驱动 · 深度项",
				Risk:     RiskDeep,
				Action:   ActionDeleteService,
				Params:   map[string]interface{}{"name": "WinDivert", "isDriver": true},
				Selected: false,
			},
		},
		Warnings: []string{"普通权限扫描"},
	}

	tmpDir := t.TempDir()
	planPath := filepath.Join(tmpDir, "plan.json")

	if err := SavePlanToFile(planPath, plan); err != nil {
		t.Fatalf("SavePlanToFile failed: %v", err)
	}

	data, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	loadedPlan, err := ReadPlanFromReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ReadPlanFromReader failed: %v", err)
	}

	if loadedPlan.Version != 2 {
		t.Errorf("Expected version 2, got %d", loadedPlan.Version)
	}
	if len(loadedPlan.Findings) != 2 {
		t.Fatalf("Expected 2 findings, got %d", len(loadedPlan.Findings))
	}
	if loadedPlan.Findings[0].ID != "svc:SangforSP" {
		t.Errorf("Finding ID mismatch: %s", loadedPlan.Findings[0].ID)
	}
	if loadedPlan.Findings[1].Risk != RiskDeep {
		t.Errorf("Finding risk mismatch: %s", loadedPlan.Findings[1].Risk)
	}
}

func TestReportWriter(t *testing.T) {
	tmpDir := t.TempDir()
	reportPath := filepath.Join(tmpDir, "report.jsonl")

	rw, err := NewReportWriter(reportPath)
	if err != nil {
		t.Fatalf("NewReportWriter failed: %v", err)
	}

	ev1 := ReportEvent{
		Event:    "start",
		Total:    2,
		Elevated: true,
		BackupID: "20261123-1000",
	}
	if err := rw.WriteEvent(ev1); err != nil {
		t.Fatalf("WriteEvent ev1 failed: %v", err)
	}

	ev2 := ReportEvent{
		Event:   "item",
		ID:      "svc:SangforSP",
		Status:  StatusOk,
		Message: "服务已删除",
	}
	if err := rw.WriteEvent(ev2); err != nil {
		t.Fatalf("WriteEvent ev2 failed: %v", err)
	}

	ev3 := ReportEvent{
		Event:  "end",
		Ok:     1,
		Failed: 0,
		Reboot: 0,
		Exit:   0,
	}
	if err := rw.WriteEvent(ev3); err != nil {
		t.Fatalf("WriteEvent ev3 failed: %v", err)
	}

	if err := rw.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	content, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	lines := bytes.Split(bytes.TrimSpace(content), []byte("\n"))
	if len(lines) != 3 {
		t.Fatalf("Expected 3 lines in report.jsonl, got %d", len(lines))
	}
}
