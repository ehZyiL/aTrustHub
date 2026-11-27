//go:build darwin

package desktop

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// systemProxyEnabled reports whether the macOS system proxy is on. The app
// tracks its own switch, so this is only used to seed the UI.
func systemProxyEnabled() bool { return false }

const macosBypassJournalFilename = "macos-proxy-bypass.json"

// bypassMu guards originalBypassDomains.
var (
	bypassMu              sync.Mutex
	originalBypassDomains = make(map[string][]string)
)

func bypassJournalPath() string {
	if systemProxyJournalDir != "" {
		return filepath.Join(systemProxyJournalDir, macosBypassJournalFilename)
	}
	if dir, err := os.UserConfigDir(); err == nil && dir != "" {
		return filepath.Join(dir, "connect-hub", macosBypassJournalFilename)
	}
	return filepath.Join(os.TempDir(), macosBypassJournalFilename)
}

// saveBypassSnapshot saves the original bypass domain mapping atomically to disk.
func saveBypassSnapshot(snapshot map[string][]string) error {
	path := bypassJournalPath()
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".macos-proxy-bypass-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if tmp != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	tmp = nil
	return os.Rename(tmpName, path)
}

// loadBypassSnapshot loads the persisted bypass mapping from disk if present.
func loadBypassSnapshot() (map[string][]string, error) {
	path := bypassJournalPath()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var snapshot map[string][]string
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return nil, err
	}
	return snapshot, nil
}

// clearBypassSnapshot deletes the recovery snapshot file.
func clearBypassSnapshot() {
	_ = os.Remove(bypassJournalPath())
}

// networkServices lists the enabled macOS network services, which system
// proxy settings are applied to.
func networkServices() ([]string, error) {
	out, err := exec.Command("networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return nil, err
	}
	var services []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "An asterisk") || strings.HasPrefix(line, "*") {
			continue
		}
		if strings.ContainsAny(line, "'\"\\") {
			continue
		}
		services = append(services, line)
	}
	return services, nil
}

// getProxyBypassDomains reads the current bypass domains for a network service.
func getProxyBypassDomains(svc string) []string {
	out, err := exec.Command("networksetup", "-getproxybypassdomains", svc).Output()
	if err != nil {
		return nil
	}
	raw := strings.TrimSpace(string(out))
	if strings.Contains(raw, "There aren't any") || strings.Contains(raw, "error") {
		return nil
	}
	var domains []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			domains = append(domains, line)
		}
	}
	return domains
}

// isPrivateNetworkEntry reports whether a bypass rule targets RFC1918 private
// networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16). These entries prevent
// VPN intranet resources from reaching the proxy.
func isPrivateNetworkEntry(entry string) bool {
	e := strings.TrimSpace(strings.ToLower(entry))
	if e == "" {
		return false
	}
	// Direct CIDR check (e.g. 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12)
	if p, err := netip.ParsePrefix(e); err == nil {
		addr := p.Addr()
		return addr.IsPrivate() || addr.IsLoopback() == false && (strings.HasPrefix(e, "10.") || strings.HasPrefix(e, "192.168.") || strings.HasPrefix(e, "172."))
	}
	// Prefix / wildcard checks commonly found in proxy switchers
	if strings.HasPrefix(e, "192.168.") || strings.HasPrefix(e, "10.") {
		return true
	}
	for i := 16; i <= 31; i++ {
		if strings.HasPrefix(e, fmt.Sprintf("172.%d.", i)) {
			return true
		}
	}
	return false
}

// sanitizeBypassDomains removes RFC1918 private network ranges from the bypass
// list so the proxy can capture intranet traffic, while preserving loopback
// and harmless host patterns.
func sanitizeBypassDomains(domains []string) []string {
	var cleaned []string
	hasLocalhost := false
	hasLoopback := false
	hasLocal := false

	for _, d := range domains {
		d = strings.TrimSpace(d)
		if d == "" || isPrivateNetworkEntry(d) {
			continue
		}
		if d == "127.0.0.1" {
			hasLoopback = true
		} else if d == "localhost" {
			hasLocalhost = true
		} else if d == "*.local" || d == "<local>" {
			hasLocal = true
		}
		cleaned = append(cleaned, d)
	}

	// Always guarantee standard loopback safety entries
	if !hasLoopback {
		cleaned = append([]string{"127.0.0.1"}, cleaned...)
	}
	if !hasLocalhost {
		cleaned = append(cleaned, "localhost")
	}
	if !hasLocal {
		cleaned = append(cleaned, "*.local")
	}
	return cleaned
}

func formatBypassCmd(svc string, domains []string) string {
	if len(domains) == 0 {
		return fmt.Sprintf("networksetup -setproxybypassdomains '%s' 'Empty'\n", svc)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "networksetup -setproxybypassdomains '%s'", svc)
	for _, d := range domains {
		fmt.Fprintf(&b, " '%s'", strings.ReplaceAll(d, "'", ""))
	}
	b.WriteString("\n")
	return b.String()
}

// applySystemProxy turns the macOS system SOCKS/HTTP/HTTPS proxy on or off
// for every enabled network service, pointing it at hostPort. It needs
// administrator rights, which macOS asks for once through osascript.
func applySystemProxy(hostPort string, on bool) error {
	host, port, ok := strings.Cut(hostPort, ":")
	if !ok || host == "" || port == "" {
		return fmt.Errorf("代理地址无效：%s", hostPort)
	}
	services, err := networkServices()
	if err != nil {
		return fmt.Errorf("读取网络服务失败：%w", err)
	}
	if len(services) == 0 {
		return fmt.Errorf("没有可设置的网络服务")
	}

	bypassMu.Lock()
	defer bypassMu.Unlock()

	var b strings.Builder
	b.WriteString("#!/bin/sh\n")

	// 关闭代理时，优先使用内存快照；若内存为空（如崩溃后重新拉起退出），从磁盘恢复
	restores := originalBypassDomains
	if !on && len(restores) == 0 {
		if loaded, err := loadBypassSnapshot(); err == nil && len(loaded) > 0 {
			restores = loaded
		}
	}

	for _, svc := range services {
		if on {
			fmt.Fprintf(&b, "networksetup -setsocksfirewallproxy '%s' %s %s\n", svc, host, port)
			fmt.Fprintf(&b, "networksetup -setwebproxy '%s' %s %s\n", svc, host, port)
			fmt.Fprintf(&b, "networksetup -setsecurewebproxy '%s' %s %s\n", svc, host, port)
			fmt.Fprintf(&b, "networksetup -setsocksfirewallproxystate '%s' on\n", svc)
			fmt.Fprintf(&b, "networksetup -setwebproxystate '%s' on\n", svc)
			fmt.Fprintf(&b, "networksetup -setsecurewebproxystate '%s' on\n", svc)

			// 自动清洗私有网段（192.168.0.0/16, 10.0.0.0/8 等），避免系统代理跳过内网资源
			orig := getProxyBypassDomains(svc)
			originalBypassDomains[svc] = orig
			cleaned := sanitizeBypassDomains(orig)
			b.WriteString(formatBypassCmd(svc, cleaned))
		} else {
			fmt.Fprintf(&b, "networksetup -setsocksfirewallproxystate '%s' off\n", svc)
			fmt.Fprintf(&b, "networksetup -setwebproxystate '%s' off\n", svc)
			fmt.Fprintf(&b, "networksetup -setsecurewebproxystate '%s' off\n", svc)

			// 退出或关闭代理时还原用户原有的绕过列表
			if orig, ok := restores[svc]; ok {
				b.WriteString(formatBypassCmd(svc, orig))
			}
		}
	}

	if on {
		// 持久化到磁盘，确保异常崩溃或被杀后配置不丢失
		_ = saveBypassSnapshot(originalBypassDomains)
	}

	f, err := os.CreateTemp("", "atrust-proxy-*.sh")
	if err != nil {
		return err
	}
	path := f.Name()
	defer os.Remove(path)
	if _, err := f.WriteString(b.String()); err != nil {
		f.Close()
		return err
	}
	f.Close()
	_ = os.Chmod(path, 0o700)

	script := fmt.Sprintf(`do shell script "/bin/sh %s" with administrator privileges`, path)
	out, err := exec.Command("osascript", "-e", script).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v：%s", err, strings.TrimSpace(string(out)))
	}

	if on {
		// 开启代理成功后启动守护看门狗，监听父进程异常退出
		startProxyWatchdog()
		return nil
	}

	// 还原成功后清除内存与磁盘持久化记录
	originalBypassDomains = make(map[string][]string)
	clearBypassSnapshot()
	return nil
}

// applySystemProxyFn is the seam tests use: unit tests must never touch the
// real system settings (that would hang on a password prompt in CI).
var applySystemProxyFn = applySystemProxy

var proxyWatchdogOnce sync.Once

func startProxyWatchdog() {
	proxyWatchdogOnce.Do(func() {
		dir := systemProxyJournalDir
		if dir == "" {
			if cfgDir, err := os.UserConfigDir(); err == nil && cfgDir != "" {
				dir = filepath.Join(cfgDir, "connect-hub")
			}
		}
		if dir == "" {
			dir = os.TempDir()
		}
		exe, err := os.Executable()
		if err != nil {
			return
		}
		cmd := exec.Command(exe, proxyWatchdogFlag, strconv.Itoa(os.Getpid()), dir)
		if err := cmd.Start(); err != nil {
			return
		}
		go func() { _ = cmd.Wait() }()
	})
}

// recoverSystemProxy 在启动时重试还原之前崩溃残留的系统代理设置。
func (a *app) recoverSystemProxy() error {
	dir := a.dir
	if dir == "" {
		return nil
	}
	restoreSystemProxyAfterDeath(dir)
	return nil
}

// restoreSystemProxyAfterDeath 在父进程消亡后（由看门狗调用）或启动恢复时调用。
// 若快照文件已被正常清理，则直接退出；若快照残留，则关闭各网卡代理并恢复原始绕过列表。
func restoreSystemProxyAfterDeath(dir string) {
	journalFile := filepath.Join(dir, macosBypassJournalFilename)
	data, err := os.ReadFile(journalFile)
	if err != nil {
		// 快照文件不存在，说明正常退出流程已成功完成恢复
		return
	}

	var snapshot map[string][]string
	_ = json.Unmarshal(data, &snapshot)

	services, err := networkServices()
	if err != nil || len(services) == 0 {
		_ = os.Remove(journalFile)
		return
	}

	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	for _, svc := range services {
		fmt.Fprintf(&b, "networksetup -setsocksfirewallproxystate '%s' off\n", svc)
		fmt.Fprintf(&b, "networksetup -setwebproxystate '%s' off\n", svc)
		fmt.Fprintf(&b, "networksetup -setsecurewebproxystate '%s' off\n", svc)
		if orig, ok := snapshot[svc]; ok {
			b.WriteString(formatBypassCmd(svc, orig))
		}
	}

	// 写入临时脚本，避免多行命令直接传入 osascript 时因换行符引发 AppleScript 语法解析错误
	tmp, err := os.CreateTemp("", "atrust-proxy-restore-*.sh")
	if err == nil {
		path := tmp.Name()
		defer os.Remove(path)
		_, _ = tmp.WriteString(b.String())
		_ = tmp.Close()
		_ = os.Chmod(path, 0o700)

		// 优先尝试直接以当前权限运行
		if err := exec.Command("/bin/sh", path).Run(); err != nil {
			// 需提权时通过 osascript 弹窗执行该临时脚本
			script := fmt.Sprintf(`do shell script "/bin/sh %s" with administrator privileges`, path)
			_ = exec.Command("osascript", "-e", script).Run()
		}
	} else {
		// 临时文件创建失败时的兜底
		_ = exec.Command("/bin/sh", "-c", b.String()).Run()
	}

	_ = os.Remove(journalFile)
}
