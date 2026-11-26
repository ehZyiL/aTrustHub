//go:build windows

package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"
)

func TestRegistryBackupLongKeyPath(t *testing.T) {
	keyPath := `Software\ConnectHubCleanupTest-` + strings.Repeat("x", 140) + filepath.Base(t.TempDir())
	k, _, err := registry.CreateKey(registry.CURRENT_USER, keyPath, registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	defer registry.DeleteKey(registry.CURRENT_USER, keyPath)
	defer k.Close()
	if err := k.SetStringValue("test", "long key survives restore"); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	m, err := CreateBackup(&Plan{Findings: []Finding{{ID: "reg:long", Action: ActionDeleteRegistry, Selected: true, Params: map[string]interface{}{"hive": "HKCU", "key": keyPath, "view": "64"}}}}, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Registry) != 1 {
		t.Fatal("missing registry backup")
	}
	if err := k.SetStringValue("test", "changed"); err != nil {
		t.Fatal(err)
	}
	if err := RestoreBackup(filepath.Join(root, m.BackupID, "manifest.json"), nil); err != nil {
		t.Fatal(err)
	}
	if v, _, err := k.GetStringValue("test"); err != nil || v != "long key survives restore" {
		t.Fatalf("restore: %q %v", v, err)
	}
}

func TestPolicyBackupRestoresOnlySelectedValue(t *testing.T) {
	for _, expand := range []bool{false, true} {
		t.Run(fmt.Sprint(expand), func(t *testing.T) {
			keyPath := `Software\ConnectHubCleanupTest-` + filepath.Base(t.TempDir())
			k, _, err := registry.CreateKey(registry.CURRENT_USER, keyPath, registry.ALL_ACCESS)
			if err != nil {
				t.Fatal(err)
			}
			defer registry.DeleteKey(registry.CURRENT_USER, keyPath)
			defer k.Close()
			const original = `Sangfor %TEMP% 测试`
			if expand {
				err = k.SetExpandStringValue("selected", original)
			} else {
				err = k.SetStringValue("selected", original)
			}
			if err != nil {
				t.Fatal(err)
			}
			f := Finding{ID: "policy:test", Action: ActionDeletePolicyValue, Selected: true, Params: map[string]interface{}{"hive": "HKCU", "key": keyPath, "value": "selected"}}
			root := t.TempDir()
			m, err := CreateBackup(&Plan{Findings: []Finding{f}}, root)
			if err != nil {
				t.Fatal(err)
			}
			if len(m.Policies) != 1 {
				t.Fatalf("policy backup missing: %d", len(m.Policies))
			}
			status, message := executeDeletePolicyValue(f)
			if status != StatusOk {
				t.Fatalf("delete: %s %s", status, message)
			}
			if _, _, err := k.GetStringValue("selected"); err != registry.ErrNotExist {
				t.Fatalf("not deleted: %v", err)
			}
			if err := k.SetStringValue("unrelated", "changed after backup"); err != nil {
				t.Fatal(err)
			}
			if err := RestoreBackup(filepath.Join(root, m.BackupID, "manifest.json"), nil); err != nil {
				t.Fatal(err)
			}
			got, typ, err := k.GetStringValue("selected")
			wantType := uint32(registry.SZ)
			if expand {
				wantType = registry.EXPAND_SZ
			}
			if err != nil || got != original || typ != wantType {
				t.Fatalf("restore: %q type=%d err=%v", got, typ, err)
			}
			if got, _, err := k.GetStringValue("unrelated"); err != nil || got != "changed after backup" {
				t.Fatalf("unrelated changed: %q %v", got, err)
			}
		})
	}
}

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
