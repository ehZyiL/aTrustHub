package localapps

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qy/easyconnect/internal/model"
)

func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == BrowserSupervisorFlag {
		if RunBrowserSupervisor(os.Stdin, os.Stdout) != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	if len(os.Args) > 1 && strings.HasPrefix(os.Args[1], "--proxy-server=") && os.Getenv("EASYCONNECT_FAKE_BROWSER") == "1" {
		data, _ := json.Marshal(os.Args[1:])
		_ = os.WriteFile(os.Getenv("EASYCONNECT_BROWSER_TEST_READY"), data, 0600)
		until := time.Now().Add(8 * time.Second)
		for time.Now().Before(until) {
			if _, err := os.Stat(os.Getenv("EASYCONNECT_BROWSER_TEST_RELEASE")); err == nil {
				os.Exit(0)
			}
			time.Sleep(10 * time.Millisecond)
		}
		os.Exit(1)
	}
	if os.Getenv("EASYCONNECT_BROWSER_LAUNCH_HELPER") == "1" {
		exe, _ := os.Executable()
		if OpenBrowser(exe, "127.0.0.1:19080", "https://portal.example/") != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func fakeBrowser(t *testing.T) (executable, ready, release string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	ready, release = filepath.Join(dir, "ready.json"), filepath.Join(dir, "release")
	t.Setenv("EASYCONNECT_FAKE_BROWSER", "1")
	t.Setenv("EASYCONNECT_BROWSER_TEST_READY", ready)
	t.Setenv("EASYCONNECT_BROWSER_TEST_RELEASE", release)
	t.Cleanup(func() { _ = os.WriteFile(release, nil, 0600) })
	return exe, ready, release
}

func waitUntil(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition did not become true")
}

func browserProfile(t *testing.T, ready string) string {
	t.Helper()
	var data []byte
	waitUntil(t, func() bool { b, err := os.ReadFile(ready); data = b; return err == nil })
	var args []string
	if err := json.Unmarshal(data, &args); err != nil {
		t.Fatal(err)
	}
	var profile string
	for _, arg := range args {
		if strings.HasPrefix(arg, "--user-data-dir=") {
			profile = strings.TrimPrefix(arg, "--user-data-dir=")
		}
	}
	if profile == "" {
		t.Fatal("independent profile missing")
	}
	proxyFound := false
	for _, arg := range args {
		if address, ok := strings.CutPrefix(arg, "--proxy-server=socks5://"); ok {
			if err := validateProxy(address); err != nil {
				t.Fatal(err)
			}
			proxyFound = true
		}
	}
	if !proxyFound {
		t.Fatal("loopback proxy missing")
	}
	for _, flag := range []string{"--disable-quic", "--dns-over-https-mode=off", "https://portal.example/"} {
		found := false
		for _, arg := range args {
			found = found || arg == flag
		}
		if !found {
			t.Fatalf("browser missing argument %q", flag)
		}
	}
	return profile
}

func TestBrowserNaturalExitAndProfileCleanup(t *testing.T) {
	exe, ready, release := fakeBrowser(t)
	m := NewManager(nil)
	defer m.Close()
	p := model.LocalApp{ID: "web", Name: "web", PointID: "point", Mode: model.LocalAppBrowser, Executable: exe, URL: "https://portal.example/"}
	if err := m.Start(p, "127.0.0.1:19080"); err != nil {
		t.Fatal(err)
	}
	if !m.View(p.ID).Running || m.View(p.ID).PID <= 0 {
		t.Fatal("browser state not running")
	}
	profile := browserProfile(t, ready)
	if err := m.Stop(p.ID); err == nil {
		t.Fatal("Stop should require user to close browser")
	}
	if err := os.WriteFile(release, nil, 0600); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, func() bool { return !m.View(p.ID).Running })
	if _, err := os.Stat(profile); !os.IsNotExist(err) {
		t.Fatalf("profile not removed: %v", err)
	}
}

func TestBrowserSupervisorOutlivesLauncher(t *testing.T) {
	exe, ready, release := fakeBrowser(t)
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), "EASYCONNECT_BROWSER_LAUNCH_HELPER=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("launcher: %v %s", err, out)
	}
	profile := browserProfile(t, ready)
	if _, err := os.Stat(profile); err != nil {
		t.Fatalf("browser profile vanished with launcher: %v", err)
	}
	if err := os.WriteFile(release, nil, 0600); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, func() bool { _, err := os.Stat(profile); return os.IsNotExist(err) })
}
