//go:build windows

package service

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBackupAndRestoreFiles(t *testing.T) {
	tmpDir := t.TempDir()
	sourceFile := filepath.Join(tmpDir, "source_test.dll")
	fileContent := []byte("fake sangfor payload test data 1234567890")
	if err := os.WriteFile(sourceFile, fileContent, 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	backupRoot := filepath.Join(tmpDir, "backups")

	plan := &Plan{
		Version:   2,
		ScannedAt: time.Now(),
		Elevated:  true,
		Findings: []Finding{
			{
				ID:       "file:" + sourceFile,
				Group:    "file",
				Action:   ActionDeletePath,
				Params:   map[string]interface{}{"path": sourceFile},
				Selected: true,
			},
		},
	}

	// 1. 测试备份创建
	manifest, err := CreateBackup(plan, backupRoot)
	if err != nil {
		t.Fatalf("CreateBackup failed: %v", err)
	}

	if manifest == nil {
		t.Fatalf("Manifest is nil")
	}

	if len(manifest.Files) != 1 {
		t.Fatalf("Expected 1 file in manifest, got %d", len(manifest.Files))
	}

	manifestPath := filepath.Join(backupRoot, manifest.BackupID, "manifest.json")
	if _, err := os.Stat(manifestPath); err != nil {
		t.Fatalf("manifest.json not found on disk: %v", err)
	}

	// 2. 测试列表备份
	backups, err := ListBackups(backupRoot)
	if err != nil {
		t.Fatalf("ListBackups failed: %v", err)
	}
	if len(backups) != 1 {
		t.Fatalf("Expected 1 backup, got %d", len(backups))
	}

	// 3. 模拟文件被删除
	if err := os.Remove(sourceFile); err != nil {
		t.Fatalf("Remove sourceFile failed: %v", err)
	}
	if _, err := os.Stat(sourceFile); !os.IsNotExist(err) {
		t.Fatalf("Expected sourceFile to be removed")
	}

	// 4. 测试一键还原
	reportPath := filepath.Join(tmpDir, "restore_report.jsonl")
	rw, err := NewReportWriter(reportPath)
	if err != nil {
		t.Fatalf("NewReportWriter failed: %v", err)
	}

	if err := RestoreBackup(manifestPath, rw); err != nil {
		t.Fatalf("RestoreBackup failed: %v", err)
	}
	_ = rw.Close()

	// 验证文件已被成功还原回原路径
	restoredData, err := os.ReadFile(sourceFile)
	if err != nil {
		t.Fatalf("Restored file cannot be read: %v", err)
	}

	if string(restoredData) != string(fileContent) {
		t.Errorf("Restored content mismatch: got %q, want %q", string(restoredData), string(fileContent))
	}
}

func TestMigrateLegacyBackups(t *testing.T) {
	tmpDir := t.TempDir()
	legacy := filepath.Join(tmpDir, "ConnectHub", "cleanup", "backups")
	target := filepath.Join(tmpDir, "connect-hub", "cleanup", "backups")

	mockBackupID := "20261124-100000"
	mockBackupDir := filepath.Join(legacy, mockBackupID)
	if err := os.MkdirAll(mockBackupDir, 0755); err != nil {
		t.Fatal(err)
	}

	testManifest := filepath.Join(mockBackupDir, "manifest.json")
	if err := os.WriteFile(testManifest, []byte(`{"version": 1}`), 0644); err != nil {
		t.Fatal(err)
	}

	migrateLegacyBackups(legacy, target)

	// 目标目录应已迁移成功
	targetManifest := filepath.Join(target, mockBackupID, "manifest.json")
	if _, err := os.Stat(targetManifest); err != nil {
		t.Fatalf("expected migrated manifest at %s: %v", targetManifest, err)
	}

	// 旧目录结构应已被清理
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatalf("expected legacy backup dir to be removed")
	}
}
