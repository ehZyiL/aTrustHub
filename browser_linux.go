//go:build linux

package main

import "os/exec"

var chromiumBrowsers = linuxChromiumBrowsers()

func linuxChromiumBrowsers() []string {
	var paths []string
	for _, name := range []string{"google-chrome-stable", "google-chrome", "chromium", "chromium-browser", "microsoft-edge-stable", "brave-browser"} {
		if path, err := exec.LookPath(name); err == nil {
			paths = append(paths, path)
		}
	}
	return paths
}
