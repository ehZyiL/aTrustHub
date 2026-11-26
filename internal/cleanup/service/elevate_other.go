//go:build !windows

package service

func IsElevated() bool {
	return false
}

func RunElevatedAndWait(exePath string, args string, hide bool) (int, error) {
	return 4, ErrUnsupported
}
