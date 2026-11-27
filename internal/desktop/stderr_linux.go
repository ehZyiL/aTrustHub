//go:build linux

package desktop

import (
	"golang.org/x/sys/unix"
	"os"
)

func redirectStderr(f *os.File) {
	_ = unix.Dup3(int(f.Fd()), 2, 0)
	os.Stderr = f
}
