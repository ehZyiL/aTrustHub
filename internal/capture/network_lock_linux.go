package capture

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Serialize transactions across helper instances. This does not lock out other
// network products; their state is inspected and never overwritten.
func (s *Service) lockNetwork(ctx context.Context) (func(), error) {
	f, err := s.openNetworkLock("transaction.lock")
	if err != nil {
		return nil, err
	}
	for {
		err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() { _ = f.Close() }, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) {
			f.Close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func (s *Service) openNetworkLock(name string) (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(s.networkDir, name), os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || sys.Uid != uint32(os.Geteuid()) {
		f.Close()
		return nil, errors.New("capture: unsafe network transaction lock")
	}
	return f, nil
}

func (s *Service) lockCaptureMode(system bool) (func(), error) {
	f, err := s.openNetworkLock("mode.lock")
	if err != nil {
		return nil, err
	}
	mode := unix.LOCK_SH
	if system {
		mode = unix.LOCK_EX
	}
	if err := unix.Flock(int(f.Fd()), mode|unix.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, errors.New("系统 TUN 和按软件接管需分别运行，请先停止当前接管模式")
		}
		return nil, err
	}
	return func() { _ = f.Close() }, nil
}
