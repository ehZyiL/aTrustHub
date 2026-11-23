//go:build !windows

package sangforclean

func IsElevated() bool {
	return false
}

func RunElevatedAndWait(exePath string, args string, hide bool) (int, error) {
	return 4, ErrUnsupported
}
