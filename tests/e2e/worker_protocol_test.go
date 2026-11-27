// Package e2e drives the real worker binary over its private IPC. It is
// deliberately black box: it needs no Hub internals, no gateway and no network,
// which is what makes it runnable on every machine (and in CI) instead of only on
// the developer's desktop.
package e2e

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// buildWorker compiles the standalone worker once per test. GOWORK=off is
// mandatory: all test and build paths must use the pinned submodule, regardless
// of an unrelated workspace or target configured by the caller.
func buildWorker(t *testing.T) string {
	t.Helper()
	src, err := filepath.Abs(filepath.Join("..", "..", "third_party", "zju-connect"))
	if err != nil {
		t.Fatal(err)
	}
	workerCmd := "cmd/connect-hub-worker"
	if _, err := os.Stat(filepath.Join(src, workerCmd, "main.go")); err != nil {
		t.Fatalf("kernel submodule missing; run git submodule update --init --recursive: %v", err)
	}
	name := "connect-hub-worker"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	out := filepath.Join(t.TempDir(), name)
	cmd := exec.Command("go", "build", "-mod=readonly", "-trimpath", "-o", out, "./"+workerCmd)
	cmd.Dir = src
	cmd.Env = workerBuildEnv()
	if build, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build worker: %v\n%s", err, build)
	}
	return out
}

// runWorker sends one control line and reads the reply (if any).
func runWorker(t *testing.T, bin, line string) (int, string) {
	t.Helper()
	cmd := exec.Command(bin)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var reply string
	go func() {
		defer close(done)
		scanner := bufio.NewScanner(stdout)
		if scanner.Scan() {
			reply = scanner.Text()
		}
	}()
	if _, err := stdin.Write([]byte(line + "\n")); err != nil {
		t.Fatal(err)
	}
	_ = stdin.Close()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("worker did not answer within 20s")
	}
	waitErr := cmd.Wait()
	code := 0
	var exit *exec.ExitError
	if errors.As(waitErr, &exit) {
		code = exit.ExitCode()
	}
	return code, strings.TrimSpace(reply)
}

type reply struct {
	Version int    `json:"version"`
	Session string `json:"session"`
	Type    string `json:"type"`
	Error   string `json:"error"`
}

func decode(t *testing.T, raw string) reply {
	t.Helper()
	if raw == "" {
		t.Fatal("worker produced no reply")
	}
	var value reply
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		t.Fatalf("reply is not JSON (%v): %s", err, raw)
	}
	return value
}

// The packaging self-check (test-worker.sh / test-worker.ps1) must keep working:
// an invalid configuration is rejected locally, before any network access.
func TestInvalidConfigurationIsRejectedWithoutNetwork(t *testing.T) {
	bin := buildWorker(t)
	code, raw := runWorker(t, bin, `{"version":7,"session":"e2e-empty","type":"start","config":{}}`)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (reply %q)", code, raw)
	}
	got := decode(t, raw)
	if got.Version != 7 || got.Session != "e2e-empty" || got.Type != "error" || got.Error == "" {
		t.Fatalf("reply = %+v", got)
	}
}

// A worker built for another protocol version refuses the session without
// answering at all: the desktop sees "handshake never completed" and its exit
// message names the mixed bundle. This is what an old worker looks like from the
// outside, so the test pins the silence, not an error frame.
func TestProtocolVersionMismatchIsRefused(t *testing.T) {
	bin := buildWorker(t)
	for _, version := range []string{"6", "8"} {
		code, raw := runWorker(t, bin, `{"version":`+version+`,"session":"e2e-mismatch","type":"start","config":{}}`)
		if code != 1 {
			t.Fatalf("version %s: exit code = %d, want 1 (reply %q)", version, code, raw)
		}
		if raw != "" {
			t.Fatalf("version %s: worker answered despite a version mismatch: %q", version, raw)
		}
	}
}

// An unknown message type is rejected the same way: exit 1, no frame.
func TestUnknownMessageTypeIsRefused(t *testing.T) {
	bin := buildWorker(t)
	code, raw := runWorker(t, bin, `{"version":7,"session":"e2e-unknown","type":"no-such-command","config":{}}`)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (reply %q)", code, raw)
	}
	if raw != "" {
		t.Fatalf("worker answered an unknown message type: %q", raw)
	}
}

func workerBuildEnv() []string {
	overrides := map[string]string{"GOWORK": "off", "GOFLAGS": "-mod=readonly", "GOOS": runtime.GOOS, "GOARCH": runtime.GOARCH, "GOTOOLCHAIN": "local", "CGO_ENABLED": "0"}
	env := make([]string, 0, len(os.Environ())+len(overrides))
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if _, override := overrides[strings.ToUpper(key)]; !override {
			env = append(env, entry)
		}
	}
	for key, value := range overrides {
		env = append(env, key+"="+value)
	}
	return env
}
