package localapps

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/ehZyiL/connect-hub/internal/model"
)

// ReadDesktopProgram reads one application already enumerated by MyGo/GIO.
// GIO's LaunchApp may activate an existing process outside our launch scope;
// here the resulting executable and argument array use the existing barrier.
// Desktop entries are data. No shell or desktop launcher evaluates the Exec.
func ReadDesktopProgram(filename string) (model.LocalApp, error) {
	f, err := os.Open(filename)
	if err != nil {
		return model.LocalApp{}, errors.New("无法读取软件入口，请重新扫描或手动选择程序")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<10 {
		return model.LocalApp{}, errors.New("软件入口不是有效的桌面文件")
	}
	return readDesktopProgram(io.LimitReader(f, 64<<10+1), filename, exec.LookPath)
}

func readDesktopProgram(r io.Reader, filename string, lookup func(string) (string, error)) (model.LocalApp, error) {
	var program model.LocalApp
	values := make(map[string]string)
	inEntry := false
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			inEntry = line == "[Desktop Entry]"
			continue
		}
		if !inEntry {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			return program, errors.New("软件入口格式无效")
		}
		switch key {
		case "Type", "Exec", "Path", "Name", "Icon", "Hidden", "Terminal", "DBusActivatable", "X-Flatpak", "TryExec":
			if _, duplicate := values[key]; duplicate {
				return program, errors.New("软件入口包含重复启动配置")
			}
			decoded, err := desktopUnescape(value)
			if err != nil {
				return program, err
			}
			values[key] = decoded
		}
	}
	if scanner.Err() != nil || values["Type"] != "Application" || values["Exec"] == "" || values["Hidden"] == "true" {
		return program, errors.New("此入口不能作为普通桌面软件启动，请手动选择程序")
	}
	if values["DBusActivatable"] == "true" || values["X-Flatpak"] != "" {
		return program, errors.New("此入口使用 D-Bus 或 Flatpak 启动，当前接管模式尚未适配")
	}
	if values["Terminal"] == "true" {
		return program, errors.New("此入口需要外部终端，请手动选择软件或终端可执行文件")
	}
	if name := values["TryExec"]; name != "" {
		if _, err := lookup(name); err != nil {
			return program, errors.New("软件入口对应的程序已不存在，请重新安装或手动选择")
		}
	}
	words, err := desktopExecWords(values["Exec"])
	if err != nil || len(words) == 0 || strings.ContainsAny(words[0], "=%") {
		return program, errors.New("无法读取此软件的启动命令，请手动选择程序和参数")
	}
	program.Executable, err = lookup(words[0])
	if err != nil || !filepath.IsAbs(program.Executable) {
		return program, errors.New("找不到此软件的可执行文件，请手动选择")
	}
	resolved, err := filepath.EvalSymlinks(program.Executable)
	if err != nil {
		return program, errors.New("此软件的可执行文件不可用")
	}
	for _, name := range []string{filepath.Base(program.Executable), filepath.Base(resolved)} {
		switch name {
		case "env", "sh", "bash", "dash", "zsh", "fish", "flatpak", "snap", "gtk-launch", "gio", "xdg-open", "systemd-run", "dbus-send", "gdbus", "pkexec", "sudo", "su":
			return program, errors.New("此入口通过启动器或命令解释器转交运行，请手动选择实际软件")
		}
	}
	for _, word := range words[1:] {
		switch word {
		case "%f", "%F", "%u", "%U", "%d", "%D", "%n", "%N", "%v", "%m":
			continue // No document or URL is being opened by this picker.
		case "%c":
			program.Args = append(program.Args, values["Name"])
		case "%k":
			program.Args = append(program.Args, filename)
		case "%i":
			if values["Icon"] != "" {
				program.Args = append(program.Args, "--icon", values["Icon"])
			}
		default:
			var literal strings.Builder
			for i := 0; i < len(word); i++ {
				if word[i] == '%' {
					if i+1 == len(word) || word[i+1] != '%' {
						return program, errors.New("此软件入口使用暂不支持的参数占位符，请手动选择程序和参数")
					}
					i++
				}
				literal.WriteByte(word[i])
			}
			program.Args = append(program.Args, literal.String())
		}
	}
	program.WorkDir = values["Path"]
	program.Name = values["Name"]
	program.ID, program.PointID, program.Mode = "selected", "selected", model.LocalAppCapture
	if err := program.Validate(); err != nil {
		return program, fmt.Errorf("软件入口配置无效：%w", err)
	}
	return program, nil
}

func desktopUnescape(text string) (string, error) {
	var out strings.Builder
	for i := 0; i < len(text); i++ {
		if text[i] != '\\' {
			out.WriteByte(text[i])
			continue
		}
		i++
		if i == len(text) {
			return "", errors.New("软件入口转义格式无效")
		}
		switch text[i] {
		case 's':
			out.WriteByte(' ')
		case 'n':
			out.WriteByte('\n')
		case 't':
			out.WriteByte('\t')
		case 'r':
			out.WriteByte('\r')
		case '\\':
			out.WriteByte('\\')
		default:
			return "", errors.New("软件入口转义格式无效，请手动选择程序")
		}
	}
	return out.String(), nil
}

// A deliberately constrained Desktop Entry Exec parser. Double quotes and
// their reserved-character escapes are supported; no shell expansion occurs.
func desktopExecWords(text string) ([]string, error) {
	var words []string
	for i := 0; i < len(text); {
		if text[i] == ' ' || text[i] == '\t' {
			i++
			continue
		}
		var word strings.Builder
		quoted := text[i] == '"'
		if quoted {
			i++
		}
		closed := !quoted
		for i < len(text) {
			ch := text[i]
			if quoted && ch == '"' {
				i++
				closed = true
				break
			}
			if !quoted && (ch == ' ' || ch == '\t') {
				break
			}
			if quoted && ch == '\\' {
				i++
				if i == len(text) || !strings.ContainsRune("\"`$\\", rune(text[i])) {
					return nil, errors.New("invalid quoted escape")
				}
				ch = text[i]
			} else if ch == 0 || ch == '\n' || ch == '\r' || (!quoted && strings.ContainsRune("\"'\\><~|&;$*?#()`", rune(ch))) || (quoted && strings.ContainsRune("`$%", rune(ch))) {
				return nil, errors.New("unsupported reserved character")
			}
			word.WriteByte(ch)
			i++
		}
		if !closed || i < len(text) && text[i] != ' ' && text[i] != '\t' {
			return nil, errors.New("invalid Exec quoting")
		}
		words = append(words, word.String())
		if len(words) > 257 {
			return nil, errors.New("too many Exec arguments")
		}
	}
	return words, nil
}
