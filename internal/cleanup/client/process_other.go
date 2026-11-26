//go:build !windows

package client

import (
	"errors"
	"os/exec"
)

func hide(cmd *exec.Cmd) {}

type child struct{ cmd *exec.Cmd }

func (c *child) Wait() error { return c.cmd.Wait() }
func (c *child) Kill() error { return c.cmd.Process.Kill() }
func launchProcess(exe string, args []string, elevated bool) (Process, error) {
	if elevated {
		return nil, errors.New("系统清理仅支持 Windows")
	}
	cmd := exec.Command(exe, args...)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &child{cmd}, nil
}
