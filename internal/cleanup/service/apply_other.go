//go:build !windows

package service

func Apply(opts ApplyOptions) (int, error) {
	return 2, ErrUnsupported
}
