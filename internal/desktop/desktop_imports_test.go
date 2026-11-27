package desktop

import (
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func desktopServiceImplementation(path string) bool {
	const prefix = "github.com/ehzyil/connect-hub/internal/"
	if path == prefix+"relay" {
		return true
	}
	if path == prefix+"relay/discovery/contract" {
		return false
	}
	for _, service := range []string{"relay/adapter", "relay/discovery", "cleanup/service"} {
		if path == prefix+service || strings.HasPrefix(path, prefix+service+"/") {
			return true
		}
	}
	return false
}

// Parse every production source file, including files for other platforms:
// a filename list would silently stop protecting declarations moved elsewhere.
func desktopRuntimeImportViolations(dir string) ([]string, error) {
	const prefix = "github.com/ehzyil/connect-hub/internal/"
	allowed := map[string]map[string]bool{
		"relay_assembly.go": {
			prefix + "relay":         true,
			prefix + "relay/adapter": true,
		},
		"discovery_assembly.go": {prefix + "relay/discovery": true},
		// app retains the injectable discovery.Backend used by assembly/tests.
		"app.go": {prefix + "relay/discovery": true},
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var violations []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, name), nil, parser.ImportsOnly)
		if err != nil {
			return nil, err
		}
		for _, imp := range file.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return nil, err
			}
			if desktopServiceImplementation(path) && !allowed[name][path] {
				violations = append(violations, fmt.Sprintf("%s: %s", name, path))
			}
		}
	}
	return violations, nil
}

func TestDesktopRuntimeImportsStayInAssembly(t *testing.T) {
	violations, err := desktopRuntimeImportViolations(filepath.Join(desktopRepoRoot(t), "internal", "desktop"))
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) != 0 {
		t.Fatalf("desktop sources import service implementations outside assembly:\n%s", strings.Join(violations, "\n"))
	}
}

func TestDesktopRuntimeImportGuard(t *testing.T) {
	const prefix = "github.com/ehzyil/connect-hub/internal/"
	tests := []struct {
		name       string
		filename   string
		importPath string
		alias      string
		violation  bool
	}{
		{"new page", "new_page.go", prefix + "relay", "", true},
		{"other platform", "new_page_linux.go", prefix + "cleanup/service", "", true},
		{"aliased runtime", "new_page.go", prefix + "relay/discovery", "backend", true},
		{"runtime subpackage", "new_page.go", prefix + "cleanup/service/extra", "", true},
		{"test fixture", "new_page_test.go", prefix + "relay", "", false},
		{"relay assembly", "relay_assembly.go", prefix + "relay", "", false},
		{"adapter assembly", "relay_assembly.go", prefix + "relay/adapter", "", false},
		{"discovery assembly", "discovery_assembly.go", prefix + "relay/discovery", "", false},
		{"backend injection", "app.go", prefix + "relay/discovery", "", false},
		{"unapproved assembly dependency", "relay_assembly.go", prefix + "cleanup/service", "", true},
		{"unapproved app dependency", "app.go", prefix + "relay", "", true},
		{"discovery contract", "new_page.go", prefix + "relay/discovery/contract", "", false},
		{"relay contract", "new_page.go", prefix + "relay/contract", "", false},
		{"cleanup client", "new_page.go", prefix + "cleanup/client", "", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			source := fmt.Sprintf("package desktop\nimport %s %q\n", test.alias, test.importPath)
			if strings.HasSuffix(test.filename, "_linux.go") {
				source = "//go:build linux\n\n" + source
			}
			if err := os.WriteFile(filepath.Join(dir, test.filename), []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			violations, err := desktopRuntimeImportViolations(dir)
			if err != nil {
				t.Fatal(err)
			}
			if got := len(violations) != 0; got != test.violation {
				t.Fatalf("violations = %v, want violation %t", violations, test.violation)
			}
		})
	}
}
