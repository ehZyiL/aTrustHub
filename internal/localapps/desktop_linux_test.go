package localapps

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDesktopEntryUsesLiteralArgumentsAndOnlyMainEntry(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "my idea")
	if err := os.WriteFile(exe, []byte("fixture"), 0700); err != nil {
		t.Fatal(err)
	}
	entry := `[Desktop Entry]
Type=Application
Name=My IDE
Exec="` + exe + `" --new-window %u %c %i %k 100%% ""
Icon=my-icon
Path=` + dir + `
[Desktop Action Other]
Exec=/must/not/run
Name=Wrong Name
`
	lookup := func(name string) (string, error) { return name, nil }
	p, err := readDesktopProgram(strings.NewReader(entry), "/desktop/my app.desktop", lookup)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"--new-window", "My IDE", "--icon", "my-icon", "/desktop/my app.desktop", "100%", ""}
	if p.Executable != exe || p.WorkDir != dir || p.Name != "My IDE" || !reflect.DeepEqual(p.Args, want) {
		t.Fatalf("entry incorrectly expanded: %+v", p)
	}
}

func TestDesktopEntryRejectsLaunchersAndAmbiguousSyntax(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "app")
	if err := os.WriteFile(exe, []byte("fixture"), 0700); err != nil {
		t.Fatal(err)
	}
	lookup := func(name string) (string, error) { return name, nil }
	for _, cmd := range []string{
		exe + `;touch /tmp/unwanted`,
		exe + ` --flag=$(touch /tmp/unwanted)`,
		exe + ` --unsupported=%U`,
		exe + ` %Q`,
		exe + ` "%u"`,
		exe + ` "unterminated`,
		exe + ` 'shell-quote'`,
		exe + ` "partial"quote`,
	} {
		if _, err := readDesktopProgram(strings.NewReader("[Desktop Entry]\nType=Application\nName=Test\nExec="+cmd), "app.desktop", lookup); err == nil {
			t.Fatalf("unsupported Exec accepted: %q", cmd)
		}
	}
	for _, extra := range []string{"DBusActivatable=true", "X-Flatpak=org.example.App", "Terminal=true", "Hidden=true", "Exec=/usr/bin/false"} {
		if _, err := readDesktopProgram(strings.NewReader("[Desktop Entry]\nType=Application\nName=Test\nExec="+exe+"\n"+extra), "app.desktop", lookup); err == nil {
			t.Fatalf("unsupported launch accepted: %s", extra)
		}
	}
	for _, name := range []string{"env", "sh", "flatpak", "gtk-launch", "systemd-run"} {
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, []byte("fixture"), 0700); err != nil {
			t.Fatal(err)
		}
		if _, err := readDesktopProgram(strings.NewReader("[Desktop Entry]\nType=Application\nExec="+path), "app.desktop", lookup); err == nil {
			t.Fatalf("indirect launcher accepted: %s", name)
		}
	}
}

func TestDesktopExecEscapesRemainLiteral(t *testing.T) {
	text, err := desktopUnescape(`"/opt/my app" "cost \\$1" "a\\\\b" "a\\"b"`)
	if err != nil {
		t.Fatal(err)
	}
	words, err := desktopExecWords(text)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"/opt/my app", "cost $1", `a\b`, `a"b`}; !reflect.DeepEqual(words, want) {
		t.Fatalf("literal escaping = %#v, want %#v", words, want)
	}
}
