// Command buildtool is the common binary builder for local development and packaging.
// Hub, Worker and patched uTLS all come from one pinned kernel submodule.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

type inputs struct {
	Go               string `json:"go"`
	KernelRepository string `json:"kernel_repository"`
	KernelCommit     string `json:"kernel_commit"`
}

type options struct {
	root, worker, out, inputPath, targetOS, arch, action string
	development                                          bool
}

type source struct {
	Commit string   `json:"commit"`
	Dirty  []string `json:"dirty,omitempty"`
}

type manifest struct {
	Schema         int                 `json:"schema"`
	Inputs         inputs              `json:"inputs"`
	InputSHA256    string              `json:"inputs_sha256"`
	Hub            source              `json:"hub"`
	Worker         source              `json:"worker"`
	Go             string              `json:"go"`
	Target         string              `json:"target"`
	GOWORK         string              `json:"gowork"`
	BuildFlags     []string            `json:"build_flags"`
	ComponentFlags map[string][]string `json:"component_flags,omitempty"`
	Components     []string            `json:"components"`
	SHA256         map[string]string   `json:"sha256"`
	Development    bool                `json:"development"`
}

type module struct {
	Path, Version, Dir string
	Replace            *module
}

func main() {
	var o options
	flag.StringVar(&o.root, "root", ".", "Hub source checkout")
	flag.StringVar(&o.worker, "worker", "", "compatibility flag; must name third_party/zju-connect inside this checkout")
	flag.StringVar(&o.out, "out", "build/debug", "output directory, relative to Hub root")
	flag.StringVar(&o.inputPath, "inputs", "packaging/build-inputs.json", "locked build inputs, relative to Hub root")
	flag.StringVar(&o.targetOS, "os", runtime.GOOS, "target OS")
	flag.StringVar(&o.arch, "arch", runtime.GOARCH, "target architecture")
	flag.StringVar(&o.action, "action", "build", "build or check (validate inputs and record module lists)")
	flag.BoolVar(&o.development, "development", false, "allow and record dirty Hub sources; kernel submodule must still match the lock")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "build: unexpected positional arguments")
		os.Exit(2)
	}
	if err := run(o); err != nil {
		fmt.Fprintln(os.Stderr, "build:", err)
		os.Exit(1)
	}
}

func run(o options) error {
	if o.action != "build" && o.action != "check" {
		return errors.New("-action must be build or check")
	}
	if o.targetOS != "windows" && o.targetOS != "linux" && o.targetOS != "darwin" {
		return fmt.Errorf("unsupported OS %q", o.targetOS)
	}
	if o.arch != "amd64" && o.arch != "arm64" {
		return fmt.Errorf("unsupported architecture %q", o.arch)
	}
	var err error
	o.root, err = filepath.Abs(o.root)
	if err != nil {
		return err
	}
	if o.worker == "" {
		o.worker = filepath.Join(o.root, "third_party", "zju-connect")
	}
	o.worker, err = filepath.Abs(o.worker)
	if err != nil {
		return err
	}
	if !samePath(o.worker, filepath.Join(o.root, "third_party", "zju-connect")) {
		return errors.New("Hub and Worker must use the same third_party/zju-connect submodule; external -worker overrides are no longer supported")
	}
	o.out = fromRoot(o.root, o.out)
	o.inputPath = fromRoot(o.root, o.inputPath)
	data, err := os.ReadFile(o.inputPath)
	if err != nil {
		return err
	}
	var lock inputs
	if err := json.Unmarshal(data, &lock); err != nil {
		return err
	}
	if lock.Go == "" || !objectID(lock.KernelCommit) || lock.KernelRepository == "" {
		return errors.New("build inputs must pin Go and kernel repository/commit")
	}
	goTool := os.Getenv("GO")
	if goTool == "" {
		goTool = "go"
	}
	goVersion, err := output(o.root, hostEnv(), goTool, "env", "GOVERSION")
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(goVersion)) != "go"+lock.Go {
		return fmt.Errorf("Go must be %s (found %s)", lock.Go, strings.TrimSpace(string(goVersion)))
	}
	hub, err := inspectSource(o.root, true)
	if err != nil {
		return err
	}
	if err := validateKernelCheckout(o.root, o.worker, lock); err != nil {
		return err
	}
	worker, err := inspectSource(o.worker, false)
	if err != nil {
		return err
	}
	if !o.development && len(hub.Dirty) != 0 {
		return fmt.Errorf("Hub has uncommitted inputs; commit them or use -development: %v", hub.Dirty)
	}
	if worker.Commit != lock.KernelCommit || len(worker.Dirty) != 0 {
		return fmt.Errorf("kernel must be clean at %s; found %s, dirty=%v", lock.KernelCommit, worker.Commit, worker.Dirty)
	}
	if err := execute(o.root, hostEnv(), goTool, "run", "./internal/workeripc/cmd/protogen", "-check", "-src", filepath.Join(o.worker, "internal/desktop/protocol.go"), "-out", "./internal/workeripc/protocol.go"); err != nil {
		return err
	}
	hubModules, err := output(o.root, hostEnv(), goTool, "list", "-m", "-json", "all")
	if err != nil {
		return err
	}
	workerModules, err := output(o.worker, hostEnv(), goTool, "list", "-m", "-json", "all")
	if err != nil {
		return err
	}
	if err := validateModules(hubModules, workerModules, o.root, o.worker); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(o.out, "core"), 0o755); err != nil {
		return err
	}
	// A failed rebuild must never leave the previous success manifest beside
	// partially replaced binaries. Packaging uses a fresh staging directory.
	if err := os.Remove(filepath.Join(o.out, "build-manifest.json")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	m := manifest{
		Schema: 2, Inputs: lock, InputSHA256: digest(data), Hub: hub, Worker: worker,
		Go: lock.Go, Target: o.targetOS + "/" + o.arch, GOWORK: "off", Development: o.development,
		BuildFlags: []string{"-mod=readonly", "-trimpath", "-buildvcs=false"},
		SHA256:     map[string]string{},
	}
	for name, content := range map[string][]byte{"desktop-modules.json": hubModules, "worker-modules.json": workerModules} {
		if err := os.WriteFile(filepath.Join(o.out, name), content, 0o644); err != nil {
			return err
		}
		m.SHA256[name] = digest(content)
	}
	if o.action == "build" {
		if err := buildBinaries(o, goTool, &m); err != nil {
			return err
		}
	}
	content, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(o.out, "build-manifest.json"), append(content, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("%s: %s; Hub %s; Worker %s; GOWORK=off; %s\n", o.action, m.Target, hub.Commit, worker.Commit, o.out)
	return nil
}

func buildBinaries(o options, goTool string, m *manifest) error {
	ext := ""
	ldflags := "-s -w"
	if o.targetOS == "windows" {
		ext = ".exe"
		ldflags += " -H=windowsgui"
		icon := filepath.Join(o.root, "appicon_windows_"+o.arch+".syso")
		f, err := os.OpenFile(icon, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err != nil {
			return fmt.Errorf("reserve generated icon (another build may be running): %w", err)
		}
		_ = f.Close()
		defer os.Remove(icon)
		if err := execute(o.root, hostEnv(), goTool, "run", "./cmd/appicon", "-icon", "resources/icon.png", "-arch", o.arch, "-out", icon); err != nil {
			return err
		}
	}
	m.BuildFlags = append(m.BuildFlags, "-ldflags="+ldflags, "CGO_ENABLED=0")
	targets := []struct{ dir, pkg, name string }{
		{o.root, ".", "connect-hub"},
		{o.worker, "./cmd/connect-hub-worker", "core/connect-hub-worker"},
	}
	if o.targetOS != "darwin" {
		targets = append(targets, struct{ dir, pkg, name string }{o.root, "./cmd/app-helper", "core/connect-hub-capture"})
	}
	targets = append(targets, struct{ dir, pkg, name string }{o.root, "./cmd/app-relay", "core/connect-hub-relay"})
	if o.targetOS == "windows" {
		targets = append(targets, struct{ dir, pkg, name string }{o.root, "./cmd/app-cleanup", "core/connect-hub-cleanup"})
	}
	for _, target := range targets {
		name := target.name + ext
		targetFlags := ldflags
		if target.pkg == "./cmd/app-cleanup" || target.pkg == "./cmd/app-relay" {
			targetFlags = "-s -w"
		} // CLI stays usable; Hub hides optional children explicitly.
		if m.ComponentFlags == nil {
			m.ComponentFlags = make(map[string][]string)
		}
		m.ComponentFlags[name] = []string{"-mod=readonly", "-trimpath", "-buildvcs=false", "-ldflags=" + targetFlags, "CGO_ENABLED=0"}
		args := []string{"build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-ldflags=" + targetFlags, "-o", filepath.Join(o.out, filepath.FromSlash(name)), target.pkg}
		if err := execute(target.dir, buildEnv(map[string]string{"GOOS": o.targetOS, "GOARCH": o.arch}), goTool, args...); err != nil {
			return err
		}
		binary, err := os.ReadFile(filepath.Join(o.out, filepath.FromSlash(name)))
		if err != nil {
			return err
		}
		m.Components = append(m.Components, name)
		m.SHA256[name] = digest(binary)
	}
	if err := os.MkdirAll(filepath.Join(o.out, "resources"), 0o755); err != nil {
		return err
	}
	icon, err := os.ReadFile(filepath.Join(o.root, "resources/icon.png"))
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(o.out, "resources/icon.png"), icon, 0o644)
}

func fromRoot(root, name string) string {
	if filepath.IsAbs(name) {
		return filepath.Clean(name)
	}
	return filepath.Join(root, name)
}

func objectID(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 20
}

func inspectSource(root string, allowWorkspace bool) (source, error) {
	commit, err := output(root, nil, "git", "rev-parse", "HEAD")
	if err != nil {
		return source{}, err
	}
	status, err := output(root, nil, "git", "status", "--porcelain=v1", "-z", "--untracked-files=all")
	if err != nil {
		return source{}, err
	}
	var dirty []string
	for _, entry := range strings.Split(string(status), "\x00") {
		if entry == "" {
			continue
		}
		if allowWorkspace && (entry == "?? go.work" || entry == "?? go.work.sum") {
			continue // Explicit GOWORK=off excludes these local inputs.
		}
		dirty = append(dirty, entry)
	}
	return source{Commit: strings.TrimSpace(string(commit)), Dirty: dirty}, nil
}

func modules(data []byte) (map[string]module, error) {
	result := map[string]module{}
	d := json.NewDecoder(bytes.NewReader(data))
	for {
		var m module
		err := d.Decode(&m)
		if errors.Is(err, io.EOF) {
			return result, nil
		}
		if err != nil {
			return nil, err
		}
		result[m.Path] = m
	}
}

func validateModules(hubData, workerData []byte, root, worker string) error {
	hub, err := modules(hubData)
	if err != nil {
		return err
	}
	work, err := modules(workerData)
	if err != nil {
		return err
	}
	const utls = "github.com/refraction-networking/utls"
	const kernel = "github.com/mythologyli/zju-connect"
	if m, ok := hub[utls]; !ok || m.Replace == nil || !samePath(m.Replace.Dir, filepath.Join(worker, "third_party/utls")) {
		return errors.New("Hub must use the kernel submodule's patched uTLS")
	}
	if m, ok := hub[kernel]; !ok || m.Replace == nil || !samePath(m.Replace.Dir, filepath.Join(root, "third_party/zju-connect")) {
		return errors.New("Hub must use its kernel submodule")
	}
	if m, ok := work[utls]; !ok || m.Replace == nil || !samePath(m.Replace.Dir, filepath.Join(worker, "third_party/utls")) {
		return errors.New("Worker must use its patched uTLS")
	}
	if m, ok := work[kernel]; !ok || m.Replace != nil || !samePath(m.Dir, worker) {
		return errors.New("Worker main module must be the kernel submodule")
	}
	return nil
}

func validateKernelCheckout(root, kernel string, lock inputs) error {
	if _, err := os.Stat(filepath.Join(kernel, ".git")); err != nil {
		return errors.New("kernel submodule is not initialized; run git submodule update --init --recursive")
	}
	entry, err := output(root, nil, "git", "ls-files", "--stage", "--", "third_party/zju-connect")
	if err != nil {
		return err
	}
	if string(entry) != "160000 "+lock.KernelCommit+" 0\tthird_party/zju-connect\n" {
		return errors.New("kernel gitlink differs from packaging/build-inputs.json")
	}
	repository, err := output(root, nil, "git", "config", "-f", ".gitmodules", "--get", "submodule.third_party/zju-connect.url")
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(repository)) != "https://github.com/"+lock.KernelRepository+".git" {
		return errors.New("kernel submodule repository differs from packaging/build-inputs.json")
	}
	return nil
}

func samePath(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
	}
	return filepath.Clean(a) == filepath.Clean(b)
}

// Override each environment key exactly once, including Windows' case-insensitive
// keys. Caller GOFLAGS/GOWORK/GOOS must not change either tools or compilation.
func buildEnv(extra map[string]string) []string {
	values := map[string]string{}
	for _, entry := range os.Environ() {
		key, value, ok := strings.Cut(entry, "=")
		if ok {
			if runtime.GOOS == "windows" {
				key = strings.ToUpper(key)
			}
			values[key] = value
		}
	}
	for key, value := range map[string]string{
		"GOWORK": "off", "GOFLAGS": "-mod=readonly", "GOTOOLCHAIN": "local",
		"GOOS": runtime.GOOS, "GOARCH": runtime.GOARCH, "CGO_ENABLED": "0",
		"GOEXPERIMENT": "", "GOAMD64": "v1", "GOARM64": "v8.0",
	} {
		values[key] = value
	}
	for key, value := range extra {
		values[key] = value
	}
	var env []string
	for key, value := range values {
		env = append(env, key+"="+value)
	}
	sort.Strings(env)
	return env
}

func hostEnv() []string { return buildEnv(nil) }

func output(dir string, env []string, name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir, cmd.Env = dir, env
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	data, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s %v in %s: %w\n%s", name, args, dir, err, stderr.String())
	}
	return data, nil
}

func execute(dir string, env []string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir, cmd.Env = dir, env
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %v in %s: %w", name, args, dir, err)
	}
	return nil
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
