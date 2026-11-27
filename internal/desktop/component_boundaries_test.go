package desktop

import (
	"encoding/json"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/ehzyil/connect-hub/internal/components"
	relayclient "github.com/ehzyil/connect-hub/internal/relay/client"
	"github.com/ehzyil/connect-hub/internal/relay/contract"
)

func desktopRepoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func TestCoreDependencyGraphExcludesOptionalRuntime(t *testing.T) {
	cmd := exec.Command("go", "list", "-mod=readonly", "-deps", "-json", "./internal/vpn", "./internal/store", "./internal/relay/client", "./internal/cleanup/client")
	cmd.Dir = desktopRepoRoot(t)
	cmd.Env = append(os.Environ(), "GOWORK=off")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("dependency graph: %v", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(out)))
	for {
		var pkg struct{ ImportPath string }
		err := dec.Decode(&pkg)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		path := pkg.ImportPath
		if path == "github.com/ehzyil/connect-hub/internal/relay" || strings.Contains(path, "/internal/relay/adapter") || path == "github.com/ehzyil/connect-hub/internal/relay/discovery" || strings.Contains(path, "/internal/relay/firewall") || strings.Contains(path, "/internal/cleanup/service") {
			t.Fatalf("core transitively depends on optional runtime: %s", path)
		}
	}
	for _, name := range []string{"lanshare.go", "lan_discovery.go", "import_relay.go", "lanshare_firewall.go", "cleanup.go", "cleanupview.go"} {
		f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(desktopRepoRoot(t), "internal", "desktop", name), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			if path == "github.com/ehzyil/connect-hub/internal/relay" || path == "github.com/ehzyil/connect-hub/internal/relay/discovery" || path == "github.com/ehzyil/connect-hub/internal/cleanup/service" {
				t.Fatalf("page %s imports sharing runtime", name)
			}
		}
	}
}

func TestDesktopDoesNotLinkCleanupService(t *testing.T) {
	cmd := exec.Command("go", "list", "-mod=readonly", "-deps", "./internal/desktop")
	cmd.Dir = desktopRepoRoot(t)
	cmd.Env = append(os.Environ(), "GOWORK=off")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "/internal/cleanup/service") {
		t.Fatal("GUI transitively links cleanup implementation")
	}
}

func TestDesktopLivesBehindCmdEntryPoint(t *testing.T) {
	root := desktopRepoRoot(t)
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".go") {
			t.Fatalf("Go source remains at repository root: %s", entry.Name())
		}
	}

	var config struct {
		Main string `json:"main"`
	}
	data, err := os.ReadFile(filepath.Join(root, "mygo.json"))
	if err != nil || json.Unmarshal(data, &config) != nil {
		t.Fatalf("read MyGo entry configuration: %v", err)
	}
	if config.Main != "cmd/connect-hub" {
		t.Fatalf("MyGo main = %q", config.Main)
	}
	cmd := exec.Command("go", "list", "-mod=readonly", "-f", "{{.Imports}}", "./cmd/connect-hub")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOWORK=off")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("list GUI entry: %v", err)
	}
	if !strings.Contains(string(out), "github.com/ehzyil/connect-hub/internal/desktop") {
		t.Fatalf("GUI entry does not invoke desktop package: %s", out)
	}

	cmd = exec.Command("go", "list", "-mod=readonly", "-deps", "./internal/localapps/takeover", "./internal/cleanup/client")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOWORK=off")
	out, err = cmd.Output()
	if err != nil {
		t.Fatalf("list extracted controller dependencies: %v", err)
	}
	if strings.Contains(string(out), "github.com/egoist/mygo") {
		t.Fatal("extracted controllers depend on MyGo")
	}
}

type sharePageStub struct {
	relayclient.Share
	view contract.View
}

func (s *sharePageStub) View() contract.View         { return s.view }
func (s *sharePageStub) Settings() contract.Settings { return contract.Settings{} }

func TestSharePageAcceptsClientAndShowsUnavailableState(t *testing.T) {
	a := testApp(t)
	a.lanShare = relayclient.Unavailable("测试组件缺失")
	a.openLANShare()
	texts := strings.Join(ui.NewTester(a.view, 1120, 800).Texts(), "|")
	if !strings.Contains(texts, "组件不可用") || strings.Contains(texts, "开启共享") {
		t.Fatalf("unavailable page: %s", texts)
	}
	stub := &sharePageStub{view: contract.View{State: contract.StateOff}}
	control := relayclient.NewLocal(stub)
	a.lanShare = control
	if got := control.Component(); got.Availability != components.Ready || got.State != components.Disabled {
		t.Fatalf("disabled installed component: %+v", got)
	}
	stub.view = contract.View{Enabled: true, State: contract.StateBlocked, Failure: "等待修复"}
	if got := control.Component(); got.Availability != components.Ready || got.State != components.Failed {
		t.Fatalf("failure was confused with installation: %+v", got)
	}
}
