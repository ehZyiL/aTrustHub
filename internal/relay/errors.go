package relay

import (
	contract "github.com/ehzyil/connect-hub/internal/relay/contract"
)

// retryableCode reports whether the server may ask for a retry.
func retryableCode(code Code) bool {
	switch code {
	case CodeBusy, CodeTargetUnreachable, CodeVPNUnavailable, CodeDialTimeout, CodeStaleResources:
		return true
	}
	return false
}

type Code = contract.Code

const CodeInvalidRequest = contract.CodeInvalidRequest

const CodeInvalidCredentials = contract.CodeInvalidCredentials

const CodeResourceDenied = contract.CodeResourceDenied

const CodeStaleResources = contract.CodeStaleResources

const CodeShareClosed = contract.CodeShareClosed

const CodeSessionExpired = contract.CodeSessionExpired

const CodeProtocolUnsupported = contract.CodeProtocolUnsupported

const CodeBusy = contract.CodeBusy

const CodeTargetUnreachable = contract.CodeTargetUnreachable

const CodeVPNUnavailable = contract.CodeVPNUnavailable

const CodeDialTimeout = contract.CodeDialTimeout

const CodeDNSUnauthorized = contract.CodeDNSUnauthorized

type Error = contract.Error

func NewError(code Code, format string, args ...any) *Error {
	return contract.NewError(code, format, args...)
}

func StatusForCode(code Code) int { return contract.StatusForCode(code) }

func CodeForStatus(status int) Code { return contract.CodeForStatus(status) }
