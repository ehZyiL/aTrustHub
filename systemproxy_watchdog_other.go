//go:build !windows

package main

// The system proxy is only managed on Windows (see platform_linux.go: Linux has
// no system proxy at all), so the proxy watchdog has nothing to do elsewhere.

func runProxyWatchdog([]string) {}
