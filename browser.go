package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ehzyil/connect-hub/internal/localapps"
	"github.com/ehzyil/connect-hub/internal/vpn"
)

func findChromium() string {
	for _, path := range chromiumBrowsers {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}
	return ""
}

// openProxyBrowser starts a Chromium-family browser in a throwaway profile
// whose SOCKS5 proxy is proxy, so the tunnel is used without touching the
// user's normal proxy settings.
func openProxyBrowser(proxy, target string) error {
	if strings.TrimSpace(proxy) == "" {
		return fmt.Errorf("没有可用的代理地址")
	}
	bin := findChromium()
	if bin == "" {
		return fmt.Errorf("没有找到 Chrome / Edge / Chromium")
	}
	return localapps.OpenBrowser(bin, proxy, target)
}

// proxyBrowserCommand is the shell command openProxyBrowser runs, for the
// clipboard when no Chromium browser is installed.
func proxyBrowserCommand(proxy, target string) string {
	bin := findChromium()
	if bin == "" {
		bin = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
	}
	parts := []string{
		fmt.Sprintf("%q", bin),
		"--proxy-server=socks5://" + proxy,
		"--user-data-dir=" + filepath.Join(os.TempDir(), "atrust-browser"),
		"--no-first-run",
	}
	if target != "" {
		parts = append(parts, fmt.Sprintf("%q", target))
	}
	return strings.Join(parts, " ")
}

// appOpenURL is the URL to open for an app: its access entry when it has
// one, else an https URL for its backend host.
func appOpenURL(app vpn.App) string {
	if app.AccessEntry != "" {
		return app.AccessEntry
	}
	if ips := app.ProbeHosts(); len(ips) == 1 {
		return "https://" + ips[0] + "/"
	}
	return ""
}
