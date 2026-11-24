//go:build darwin

package localapps

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadDarwinProgramBundle(t *testing.T) {
	tempDir := t.TempDir()
	appDir := filepath.Join(tempDir, "Sample.app")
	contentsDir := filepath.Join(appDir, "Contents")
	macosDir := filepath.Join(contentsDir, "MacOS")

	if err := os.MkdirAll(macosDir, 0o755); err != nil {
		t.Fatalf("failed to create app directories: %v", err)
	}

	execPath := filepath.Join(macosDir, "SampleExec")
	if err := os.WriteFile(execPath, []byte("#!/bin/sh\necho hello\n"), 0o755); err != nil {
		t.Fatalf("failed to create executable: %v", err)
	}

	plistContent := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDisplayName</key>
	<string>Sample App</string>
	<key>CFBundleExecutable</key>
	<string>SampleExec</string>
	<key>CFBundleName</key>
	<string>Sample</string>
</dict>
</plist>`
	if err := os.WriteFile(filepath.Join(contentsDir, "Info.plist"), []byte(plistContent), 0o644); err != nil {
		t.Fatalf("failed to write Info.plist: %v", err)
	}

	app, err := ReadDarwinProgram(appDir)
	if err != nil {
		t.Fatalf("ReadDarwinProgram failed: %v", err)
	}

	if app.Name != "Sample App" {
		t.Errorf("expected app.Name to be 'Sample App', got %q", app.Name)
	}
	if filepath.Base(app.Executable) != "SampleExec" {
		t.Errorf("expected Executable to end with 'SampleExec', got %q", app.Executable)
	}
	if app.WorkDir != macosDir {
		t.Errorf("expected WorkDir to be %q, got %q", macosDir, app.WorkDir)
	}
}

func TestReadDarwinProgramFallbackExec(t *testing.T) {
	tempDir := t.TempDir()
	appDir := filepath.Join(tempDir, "Fallback.app")
	macosDir := filepath.Join(appDir, "Contents", "MacOS")

	if err := os.MkdirAll(macosDir, 0o755); err != nil {
		t.Fatalf("failed to create app directories: %v", err)
	}

	execPath := filepath.Join(macosDir, "fallback_bin")
	if err := os.WriteFile(execPath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("failed to write executable: %v", err)
	}

	// 没有提供 Info.plist，测试目录自动探测
	app, err := ReadDarwinProgram(appDir)
	if err != nil {
		t.Fatalf("ReadDarwinProgram failed: %v", err)
	}

	if app.Name != "Fallback" {
		t.Errorf("expected app.Name to be 'Fallback', got %q", app.Name)
	}
	if filepath.Base(app.Executable) != "fallback_bin" {
		t.Errorf("expected Executable to be fallback_bin, got %q", app.Executable)
	}
}
