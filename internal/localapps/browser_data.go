package localapps

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// populateUserData clones bookmarks and collects installed extensions from
// the user's primary Chromium profile into the temporary user-data-dir.
// This allows the proxy browser to have the user's familiar bookmarks and
// extensions without locking the primary browser's profile directory.
func populateUserData(executable, targetDir string) (loadExtensions []string) {
	sourceBase := findChromiumUserDataDir(executable)
	if sourceBase == "" {
		return nil
	}

	// Find the active profile directory (usually "Default" or "Profile 1")
	profileDir := ""
	for _, candidate := range []string{"Default", "Profile 1", "Profile 2"} {
		p := filepath.Join(sourceBase, candidate)
		if hasBookmarks(p) {
			profileDir = p
			break
		}
	}
	if profileDir == "" {
		// Fallback to Default even if Bookmarks not found yet
		profileDir = filepath.Join(sourceBase, "Default")
	}

	targetDefault := filepath.Join(targetDir, "Default")
	_ = os.MkdirAll(targetDefault, 0700)

	// Copy bookmarks
	accountBM := filepath.Join(profileDir, "AccountBookmarks")
	regularBM := filepath.Join(profileDir, "Bookmarks")
	targetRegular := filepath.Join(targetDefault, "Bookmarks")

	if info, err := os.Stat(accountBM); err == nil && !info.IsDir() && info.Size() > 0 {
		_ = copyFile(accountBM, targetRegular)
		_ = copyFile(accountBM, filepath.Join(targetDefault, "AccountBookmarks"))
	} else if info, err := os.Stat(regularBM); err == nil && !info.IsDir() && info.Size() > 0 {
		_ = copyFile(regularBM, targetRegular)
	}

	// Copy Favicons for bookmark icons if available
	_ = copyFile(filepath.Join(profileDir, "Favicons"), filepath.Join(targetDefault, "Favicons"))

	// Ensure bookmark bar is always visible by default
	prefs := `{"bookmark_bar":{"show_on_all_tabs":true}}`
	_ = os.WriteFile(filepath.Join(targetDefault, "Preferences"), []byte(prefs), 0600)

	// Collect extensions with manifest.json
	extensionsBase := filepath.Join(profileDir, "Extensions")
	if entries, err := os.ReadDir(extensionsBase); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			extDir := filepath.Join(extensionsBase, e.Name())
			versions, err := os.ReadDir(extDir)
			if err != nil {
				continue
			}
			for _, v := range versions {
				if !v.IsDir() {
					continue
				}
				vPath := filepath.Join(extDir, v.Name())
				if _, err := os.Stat(filepath.Join(vPath, "manifest.json")); err == nil {
					loadExtensions = append(loadExtensions, vPath)
					break // Pick the first valid version for this extension
				}
			}
			if len(loadExtensions) >= 40 {
				break
			}
		}
	}

	return loadExtensions
}

func hasBookmarks(profileDir string) bool {
	for _, name := range []string{"AccountBookmarks", "Bookmarks"} {
		if info, err := os.Stat(filepath.Join(profileDir, name)); err == nil && !info.IsDir() && info.Size() > 0 {
			return true
		}
	}
	return false
}

func findChromiumUserDataDir(executable string) string {
	lower := strings.ToLower(executable)
	isEdge := strings.Contains(lower, "edge")

	switch runtime.GOOS {
	case "windows":
		localAppData := os.Getenv("LOCALAPPDATA")
		if localAppData == "" {
			return ""
		}
		if isEdge {
			return filepath.Join(localAppData, "Microsoft", "Edge", "User Data")
		}
		// Default to Google Chrome
		chromeDir := filepath.Join(localAppData, "Google", "Chrome", "User Data")
		if _, err := os.Stat(chromeDir); err == nil {
			return chromeDir
		}
		// Fallback to Edge or Chromium
		edgeDir := filepath.Join(localAppData, "Microsoft", "Edge", "User Data")
		if _, err := os.Stat(edgeDir); err == nil {
			return edgeDir
		}
		return filepath.Join(localAppData, "Chromium", "User Data")

	case "darwin":
		home, _ := os.UserHomeDir()
		if home == "" {
			return ""
		}
		if isEdge {
			return filepath.Join(home, "Library", "Application Support", "Microsoft Edge")
		}
		return filepath.Join(home, "Library", "Application Support", "Google", "Chrome")

	case "linux":
		home, _ := os.UserHomeDir()
		if home == "" {
			return ""
		}
		config := os.Getenv("XDG_CONFIG_HOME")
		if config == "" {
			config = filepath.Join(home, ".config")
		}
		if isEdge {
			return filepath.Join(config, "microsoft-edge")
		}
		chromeDir := filepath.Join(config, "google-chrome")
		if _, err := os.Stat(chromeDir); err == nil {
			return chromeDir
		}
		return filepath.Join(config, "chromium")
	}

	return ""
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
