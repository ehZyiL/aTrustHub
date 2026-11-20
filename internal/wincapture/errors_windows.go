package wincapture

import (
	"errors"
	"fmt"
	"syscall"
)

// The helper transports errors as text. Include the failing API and numeric
// Win32 code here, before the error crosses the pipe and loses its type.
func windowsError(operation string, err error) error {
	if err == nil {
		return nil
	}
	var code syscall.Errno
	if errors.As(err, &code) {
		return fmt.Errorf("%s（Win32 %d）：%w", operation, uint32(code), err)
	}
	return fmt.Errorf("%s：%w", operation, err)
}
