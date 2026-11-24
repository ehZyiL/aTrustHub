//go:build darwin

package localapps

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ehzyil/connect-hub/internal/model"
)

var (
	xmlExecutableRegex  = regexp.MustCompile(`<key>CFBundleExecutable</key>\s*<string>([^<]+)</string>`)
	xmlDisplayNameRegex = regexp.MustCompile(`<key>CFBundleDisplayName</key>\s*<string>([^<]+)</string>`)
	xmlNameRegex        = regexp.MustCompile(`<key>CFBundleName</key>\s*<string>([^<]+)</string>`)
)

// ReadDarwinProgram 解析 macOS 上的已安装应用入口（.app bundle 或独立可执行文件）。
func ReadDarwinProgram(path string) (model.LocalApp, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return model.LocalApp{}, errors.New("软件路径不能为空")
	}

	fi, err := os.Stat(path)
	if err != nil {
		return model.LocalApp{}, fmt.Errorf("找不到指定的软件路径：%w", err)
	}

	// 场景 1：如果选择的是普通的独立可执行文件
	if !fi.IsDir() {
		if fi.Mode()&0111 == 0 {
			return model.LocalApp{}, fmt.Errorf("文件 %s 没有可执行权限", filepath.Base(path))
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			abs = path
		}
		return model.LocalApp{
			Name:       strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)),
			Executable: abs,
			WorkDir:    filepath.Dir(abs),
			Mode:       model.LocalAppBrowser,
		}, nil
	}

	// 场景 2：macOS .app Bundle 目录
	var appDir string
	if strings.HasSuffix(strings.ToLower(path), ".app") {
		appDir = path
	} else if strings.Contains(strings.ToLower(path), ".app/") {
		// 用户传入了 .app 内部子路径，截取到 .app 根目录
		idx := strings.Index(strings.ToLower(path), ".app")
		appDir = path[:idx+4]
	} else {
		// 普通目录，尝试检查内部是否有 Contents/Info.plist
		if _, err := os.Stat(filepath.Join(path, "Contents", "Info.plist")); err == nil {
			appDir = path
		}
	}

	if appDir == "" {
		return model.LocalApp{}, errors.New("所选目录不是有效的 macOS 应用程序包 (.app)")
	}

	return parseAppBundle(appDir)
}

func parseAppBundle(appDir string) (model.LocalApp, error) {
	plistPath := filepath.Join(appDir, "Contents", "Info.plist")
	macosDir := filepath.Join(appDir, "Contents", "MacOS")

	var appName string
	var execName string

	// 优先尝试读取并正则匹配 XML 格式的 Info.plist
	if data, err := os.ReadFile(plistPath); err == nil {
		if m := xmlExecutableRegex.FindSubmatch(data); len(m) > 1 {
			execName = strings.TrimSpace(string(m[1]))
		}
		if m := xmlDisplayNameRegex.FindSubmatch(data); len(m) > 1 {
			appName = strings.TrimSpace(string(m[1]))
		} else if m := xmlNameRegex.FindSubmatch(data); len(m) > 1 {
			appName = strings.TrimSpace(string(m[1]))
		}
	}

	// 如果未能提取到可执行文件名（可能是苹果二进制 bplist 格式），调用 plutil 提取
	if execName == "" {
		if out, err := exec.Command("/usr/bin/plutil", "-extract", "CFBundleExecutable", "raw", "-o", "-", plistPath).Output(); err == nil {
			execName = strings.TrimSpace(string(out))
		}
	}
	if appName == "" {
		if out, err := exec.Command("/usr/bin/plutil", "-extract", "CFBundleDisplayName", "raw", "-o", "-", plistPath).Output(); err == nil && len(bytes.TrimSpace(out)) > 0 {
			appName = strings.TrimSpace(string(out))
		} else if out, err := exec.Command("/usr/bin/plutil", "-extract", "CFBundleName", "raw", "-o", "-", plistPath).Output(); err == nil {
			appName = strings.TrimSpace(string(out))
		}
	}

	if appName == "" {
		appName = strings.TrimSuffix(filepath.Base(appDir), ".app")
	}

	// 校验并定位真正的二进制
	var finalExecutable string
	if execName != "" {
		target := filepath.Join(macosDir, execName)
		if fi, err := os.Stat(target); err == nil && !fi.IsDir() {
			finalExecutable = target
		}
	}

	// 兜底方案：遍历 Contents/MacOS 目录找到第一个可执行文件
	if finalExecutable == "" {
		entries, err := os.ReadDir(macosDir)
		if err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				full := filepath.Join(macosDir, entry.Name())
				if fi, err := os.Stat(full); err == nil && fi.Mode()&0111 != 0 {
					finalExecutable = full
					break
				}
			}
		}
	}

	if finalExecutable == "" {
		return model.LocalApp{}, fmt.Errorf("无法在应用包 %s 中找到可执行二进制文件", filepath.Base(appDir))
	}

	absExec, err := filepath.Abs(finalExecutable)
	if err != nil {
		absExec = finalExecutable
	}

	return model.LocalApp{
		Name:       appName,
		Executable: absExec,
		WorkDir:    macosDir,
		Mode:       model.LocalAppBrowser,
	}, nil
}
