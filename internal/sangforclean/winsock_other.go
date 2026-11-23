//go:build !windows

package sangforclean

func UninstallWinsockProvider(providerIdHex string, isNameSpace bool) error {
	return ErrUnsupported
}

func NetshWinsockReset() error {
	return ErrUnsupported
}
