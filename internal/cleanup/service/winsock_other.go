//go:build !windows

package service

func UninstallWinsockProvider(providerIdHex string, isNameSpace bool) error {
	return ErrUnsupported
}

func NetshWinsockReset() error {
	return ErrUnsupported
}
