//go:build !windows

package taskio

import "os"

func privateDir(dir string) error { return os.Mkdir(dir, 0700) }

func sharingViolation(error) bool { return false }
