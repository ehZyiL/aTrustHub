package wincapture

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestHelperPathPrefersCoreAndFallsBackToFlat(t *testing.T) {
	root := t.TempDir()
	gui := filepath.Join(root, "easyconnect-hub.exe")
	writeFile(t, gui)
	if got, ok := helperPath(gui); ok {
		t.Fatalf("helper found without any file on disk: %q", got)
	}

	flat := filepath.Join(root, "easyconnect-hub-capture.exe")
	writeFile(t, flat)
	if got, ok := helperPath(gui); !ok || got != flat {
		t.Fatalf("flat layout not used: %q %v", got, ok)
	}

	core := filepath.Join(root, coreDir, "easyconnect-hub-capture.exe")
	writeFile(t, core)
	if got, ok := helperPath(gui); !ok || got != core {
		t.Fatalf("core layout must win over the flat copy: %q %v", got, ok)
	}
}

func TestHelperPathSurvivesBundleInCoreNamedFolder(t *testing.T) {
	// 用户把压缩包解压到名为 core 的目录，两种布局都必须仍然找得到助手。
	bundle := filepath.Join(t.TempDir(), "core")
	flatGUI := filepath.Join(bundle, "easyconnect-hub.exe")
	writeFile(t, filepath.Join(bundle, "easyconnect-hub-capture.exe"))
	if got, ok := helperPath(flatGUI); !ok || got != filepath.Join(bundle, "easyconnect-hub-capture.exe") {
		t.Fatalf("flat bundle inside a core folder: %q %v", got, ok)
	}
	coreGUI := filepath.Join(bundle, coreDir, "easyconnect-hub.exe")
	writeFile(t, coreGUI)
	coreHelper := filepath.Join(bundle, coreDir, coreDir, "easyconnect-hub-capture.exe")
	writeFile(t, coreHelper)
	if got, ok := helperPath(coreGUI); !ok || got != coreHelper {
		t.Fatalf("core bundle inside a core folder: %q %v", got, ok)
	}
}

func TestBundleRootCoversShippedAndLegacyLayouts(t *testing.T) {
	root := filepath.Join(t.TempDir(), "easyconnect-hub-windows-amd64")
	for _, exe := range []string{
		filepath.Join(root, "easyconnect-hub.exe"),
		filepath.Join(root, "easyconnect-hub-capture.exe"),
		filepath.Join(root, coreDir, "easyconnect-hub-capture.exe"),
	} {
		if got := bundleRoot(exe); got != root {
			t.Fatalf("bundleRoot(%q) = %q, want %q", exe, got, root)
		}
	}
}

func TestVerifyExecutableAcceptsBothLayoutDirectories(t *testing.T) {
	// GUI 与助手的目录组合：core/ 布局下助手在子目录，父进程在包根目录。
	root := filepath.Join(t.TempDir(), "bundle")
	core := filepath.Join(root, coreDir)
	helper := filepath.Join(core, "easyconnect-hub-capture.exe")
	allowed := []string{filepath.Dir(helper), bundleRoot(helper)}
	if allowed[0] != core || allowed[1] != root {
		t.Fatalf("unexpected allowed directories: %v", allowed)
	}
	flat := filepath.Join(root, "easyconnect-hub-capture.exe")
	if dirs := []string{filepath.Dir(flat), bundleRoot(flat)}; dirs[0] != root || dirs[1] != root {
		t.Fatalf("unexpected flat allowed directories: %v", dirs)
	}
}
