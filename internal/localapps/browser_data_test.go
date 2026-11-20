package localapps

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPopulateUserData(t *testing.T) {
	tempBase := t.TempDir()
	sourceDir := filepath.Join(tempBase, "Default")
	if err := os.MkdirAll(filepath.Join(sourceDir, "Extensions", "my-ext-id", "1.0_0"), 0755); err != nil {
		t.Fatal(err)
	}
	manifest := `{"name": "test-ext", "version": "1.0"}`
	if err := os.WriteFile(filepath.Join(sourceDir, "Extensions", "my-ext-id", "1.0_0", "manifest.json"), []byte(manifest), 0644); err != nil {
		t.Fatal(err)
	}
	bookmarksContent := `{"roots": {"bookmark_bar": {"children": [{"name": "My Corp", "url": "https://corp.example"}]}}}`
	if err := os.WriteFile(filepath.Join(sourceDir, "AccountBookmarks"), []byte(bookmarksContent), 0644); err != nil {
		t.Fatal(err)
	}

	targetDir := t.TempDir()
	var realChromeDir string
	switch runtime.GOOS {
	case "windows":
		t.Setenv("LOCALAPPDATA", tempBase)
		realChromeDir = filepath.Join(tempBase, "Google", "Chrome", "User Data", "Default")
	case "linux":
		t.Setenv("XDG_CONFIG_HOME", tempBase)
		realChromeDir = filepath.Join(tempBase, "google-chrome", "Default")
	case "darwin":
		t.Setenv("HOME", tempBase)
		realChromeDir = filepath.Join(tempBase, "Library", "Application Support", "Google", "Chrome", "Default")
	default:
		t.Skip("Chromium profile discovery is unsupported on this platform")
	}
	if err := os.MkdirAll(filepath.Join(realChromeDir, "Extensions", "my-ext-id", "1.0_0"), 0755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(realChromeDir, "Extensions", "my-ext-id", "1.0_0", "manifest.json"), []byte(manifest), 0644)
	_ = os.WriteFile(filepath.Join(realChromeDir, "AccountBookmarks"), []byte(bookmarksContent), 0644)

	exts := populateUserData("chrome.exe", targetDir)
	if len(exts) != 1 {
		t.Fatalf("expected 1 extension loaded, got %d (%v)", len(exts), exts)
	}

	// Verify target Bookmarks file exists and has content
	targetBM := filepath.Join(targetDir, "Default", "Bookmarks")
	data, err := os.ReadFile(targetBM)
	if err != nil {
		t.Fatalf("target Bookmarks not copied: %v", err)
	}
	if string(data) != bookmarksContent {
		t.Fatalf("content mismatch: got %s, want %s", string(data), bookmarksContent)
	}
}
