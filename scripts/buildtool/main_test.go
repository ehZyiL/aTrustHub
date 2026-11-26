package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The same input must resolve identically regardless of the caller's directory.
func TestBuildContextIgnoresAmbientWorkspaceAndTarget(t *testing.T) {
	t.Setenv("GOWORK", filepath.Join(t.TempDir(), "wrong.work"))
	t.Setenv("GOFLAGS", "-mod=mod -tags=unexpected")
	t.Setenv("GOOS", "plan9")
	t.Setenv("GOTOOLCHAIN", "auto")
	env := buildEnv(map[string]string{"GOOS": "linux", "GOARCH": "arm64"})
	seen := map[string]string{}
	for _, entry := range env {
		key, value, _ := strings.Cut(entry, "=")
		if runtime.GOOS == "windows" {
			key = strings.ToUpper(key)
		}
		if _, exists := seen[key]; exists {
			t.Fatalf("duplicate environment key %q", key)
		}
		seen[key] = value
	}
	for key, want := range map[string]string{"GOWORK": "off", "GOFLAGS": "-mod=readonly", "GOOS": "linux", "GOARCH": "arm64", "GOTOOLCHAIN": "local", "CGO_ENABLED": "0"} {
		if seen[key] != want {
			t.Fatalf("%s=%q, want %q", key, seen[key], want)
		}
	}
}

func TestWrongKernelAndUTLSAreRejected(t *testing.T) {
	root, worker := t.TempDir(), t.TempDir()
	kernel := module{Path: "github.com/mythologyli/zju-connect", Replace: &module{Dir: filepath.Join(root, "third_party/zju-connect")}}
	upstream := module{Path: "github.com/refraction-networking/utls", Version: "v1.8.2"}
	patched := module{Path: upstream.Path, Replace: &module{Dir: filepath.Join(worker, "third_party/utls")}}
	encode := func(ms ...module) []byte {
		var data []byte
		for _, m := range ms {
			b, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			data = append(data, b...)
			data = append(data, '\n')
		}
		return data
	}
	for _, tc := range []struct {
		name      string
		hub, work []byte
		valid     bool
	}{
		{"explicit baseline", encode(kernel, upstream), encode(patched), true},
		{"root workspace leaks patched TLS into Hub", encode(kernel, patched), encode(patched), false},
		{"Hub workspace strips worker TLS patch", encode(kernel, upstream), encode(upstream), false},
		{"Hub links a second external kernel", encode(module{Path: kernel.Path, Replace: &module{Dir: worker}}, upstream), encode(patched), false},
		{"incomplete module list", encode(kernel), encode(patched), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateModules(tc.hub, tc.work, root, worker)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
		})
	}
}

func TestSourceIncludesUntrackedCodeButExcludesExplicitLocalWorkspace(t *testing.T) {
	root := t.TempDir()
	for _, args := range [][]string{
		{"init", "--quiet"},
		{"-c", "user.name=Build Test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false", "commit", "--allow-empty", "--quiet", "-m", "fixture"},
	} {
		if _, err := output(root, nil, "git", args...); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"go.work", "go.work.sum", "unexpected.go"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	hub, err := inspectSource(root, true)
	if err != nil {
		t.Fatal(err)
	}
	if !objectID(hub.Commit) || len(hub.Dirty) != 1 || hub.Dirty[0] != "?? unexpected.go" {
		t.Fatalf("unexpected Hub status: %+v", hub)
	}
	worker, err := inspectSource(root, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(worker.Dirty) != 3 {
		t.Fatalf("Worker ignored an input: %+v", worker)
	}
}
