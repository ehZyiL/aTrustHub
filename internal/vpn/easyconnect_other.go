//go:build !windows

package vpn

import "os/exec"

func hideWorkerCmd(cmd *exec.Cmd) {}
