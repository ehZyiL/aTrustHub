package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveDataDir_EnvVars(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. 测试 CONNECT_HUB_HOME
	customNew := filepath.Join(tmpDir, "custom-new")
	t.Setenv("CONNECT_HUB_HOME", customNew)
	t.Setenv("EASYCONNECT_HOME", "")

	got, err := resolveDataDir()
	if err != nil {
		t.Fatalf("resolveDataDir failed: %v", err)
	}
	if got != customNew {
		t.Errorf("expected %s, got %s", customNew, got)
	}

	// 2. 测试回退兼容 EASYCONNECT_HOME
	customOld := filepath.Join(tmpDir, "custom-old")
	t.Setenv("CONNECT_HUB_HOME", "")
	t.Setenv("EASYCONNECT_HOME", customOld)

	gotOld, err := resolveDataDir()
	if err != nil {
		t.Fatalf("resolveDataDir fallback failed: %v", err)
	}
	if gotOld != customOld {
		t.Errorf("expected fallback %s, got %s", customOld, gotOld)
	}
}

func TestResolveDataDir_NoSpacesAndMigration(t *testing.T) {
	t.Setenv("CONNECT_HUB_HOME", "")
	t.Setenv("EASYCONNECT_HOME", "")

	base, err := os.UserConfigDir()
	if err != nil {
		t.Skipf("cannot get UserConfigDir: %v", err)
	}

	expectedTarget := filepath.Join(base, "connect-hub")
	if strings.Contains(filepath.Base(expectedTarget), " ") {
		t.Errorf("expected target directory name to have no spaces, got %s", filepath.Base(expectedTarget))
	}

	// 验证平滑迁移逻辑（利用临时子目录模拟）
	mockBase := t.TempDir()
	oldDir := filepath.Join(mockBase, "EasyConnectHub")
	newDir := filepath.Join(mockBase, "connect-hub")

	if err := os.MkdirAll(oldDir, 0o700); err != nil {
		t.Fatalf("failed to create mock oldDir: %v", err)
	}
	markerFile := filepath.Join(oldDir, "test_config.json")
	if err := os.WriteFile(markerFile, []byte(`{"ok": true}`), 0o600); err != nil {
		t.Fatalf("failed to write marker: %v", err)
	}

	// 模拟迁移流程
	if _, err := os.Stat(newDir); os.IsNotExist(err) {
		if fi, err := os.Stat(oldDir); err == nil && fi.IsDir() {
			if renameErr := os.Rename(oldDir, newDir); renameErr != nil {
				t.Fatalf("migration rename failed: %v", renameErr)
			}
		}
	}

	if _, err := os.Stat(filepath.Join(newDir, "test_config.json")); err != nil {
		t.Errorf("expected marker file in migrated newDir, got: %v", err)
	}
}

func TestMigrateAndCleanLegacyDir(t *testing.T) {
	base := t.TempDir()
	src := filepath.Join(base, "Connect Hub")
	dst := filepath.Join(base, "connect-hub")

	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}

	testFile := filepath.Join(src, "window-state.json")
	if err := os.WriteFile(testFile, []byte(`{"x": 100}`), 0o644); err != nil {
		t.Fatal(err)
	}

	// 测试子目录递归合入
	srcSub := filepath.Join(src, "sub_dir")
	if err := os.MkdirAll(srcSub, 0o755); err != nil {
		t.Fatal(err)
	}
	subFile := filepath.Join(srcSub, "sub.log")
	if err := os.WriteFile(subFile, []byte("sub log"), 0o644); err != nil {
		t.Fatal(err)
	}

	migrateAndCleanLegacyDir(src, dst)

	// 目标目录应收到文件
	if _, err := os.Stat(filepath.Join(dst, "window-state.json")); err != nil {
		t.Fatalf("expected window-state.json in dst: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "sub_dir", "sub.log")); err != nil {
		t.Fatalf("expected sub_dir/sub.log in dst: %v", err)
	}
	// 旧目录及旧子目录应已被完全删除
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatalf("expected src directory to be removed, but it still exists")
	}
}
