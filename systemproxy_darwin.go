//go:build darwin

package main

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
)

// systemProxyEnabled reports whether the macOS system proxy is on. The app
// tracks its own switch, so this is only used to seed the UI.
func systemProxyEnabled() bool { return false }

// bypassMu guards originalBypassDomains.
var (
	bypassMu              sync.Mutex
	originalBypassDomains = make(map[string][]string)
)

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
			if orig, ok := originalBypassDomains[svc]; ok {
				b.WriteString(formatBypassCmd(svc, orig))
				delete(originalBypassDomains, svc)
			}
		}
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
	return nil
}

// applySystemProxyFn is the seam tests use: unit tests must never touch the
// real system settings (that would hang on a password prompt in CI).
var applySystemProxyFn = applySystemProxy
