package main

import (
	"github.com/ehZyiL/connect-hub/internal/capture"
	"os"
)

func runCaptureLauncher() bool {
	if len(os.Args) != 2 || os.Args[1] != capture.LauncherFlag {
		return false
	}
	if err := capture.RunLaunchBarrier(os.Stdin, os.Stdout); err != nil {
		os.Exit(1)
	}
	return true
}
