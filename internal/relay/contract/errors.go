// Package contract owns sharing DTOs, validation and typed errors. It does not
// construct a server, transport, discovery backend or VPN session.
package contract

import (
	"fmt"
	"net/http"
)

// Code is a stable wire error code. Clients switch on it and never match the
// human-readable message.
type Code string

const (
	// CodeInvalidRequest is malformed input or a protocol misuse.
	CodeInvalidRequest Code = "invalid_request"
	// CodeInvalidCredentials is a failed token authentication.
	CodeInvalidCredentials Code = "invalid_credentials"
	// CodeResourceDenied means the target is not authorized by the share.
	CodeResourceDenied Code = "resource_denied"
	// CodeStaleResources means the client used an outdated epoch/revision.
	CodeStaleResources Code = "stale_resources"
	// CodeShareClosed means the share was switched off.
	CodeShareClosed Code = "share_closed"
	// CodeSessionExpired means the client lease ran out.
	CodeSessionExpired Code = "session_expired"
	// CodeProtocolUnsupported means a version mismatch.
	CodeProtocolUnsupported Code = "protocol_unsupported"
	// CodeBusy is a rate or concurrency limit.
	CodeBusy Code = "busy"
	// CodeTargetUnreachable is a failed upstream dial.
	CodeTargetUnreachable Code = "target_unreachable"
	// CodeVPNUnavailable means the bound access point is not usable.
	CodeVPNUnavailable Code = "vpn_unavailable"
	// CodeDialTimeout is a per-request upstream timeout.
	CodeDialTimeout Code = "dial_timeout"
	// CodeDNSUnauthorized means the queried name is outside the share scope.
	CodeDNSUnauthorized Code = "dns_unauthorized"
)

// Error is a typed protocol failure. Message is for humans, Code for programs.
type Error struct {
	Code      Code   `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
	RequestID string `json:"requestId,omitempty"`
	// Status overrides the default HTTP status when non-zero.
	Status int `json:"-"`
}

// NewError builds a protocol error with the default status of its code.
func NewError(code Code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return string(e.Code) + ": " + e.Message
}

// HTTPStatus maps a code to its status, so the client can fall back to the
// status line when a body is missing.
func (e *Error) HTTPStatus() int {
	if e == nil {
		return http.StatusOK
	}
	if e.Status != 0 {
		return e.Status
	}
	return StatusForCode(e.Code)
}

// StatusForCode is the canonical HTTP status of a wire code.
func StatusForCode(code Code) int {
	switch code {
	case CodeInvalidRequest:
		return http.StatusBadRequest
	case CodeInvalidCredentials:
		return http.StatusUnauthorized
	case CodeResourceDenied, CodeDNSUnauthorized:
		return http.StatusForbidden
	case CodeStaleResources:
		return http.StatusConflict
	case CodeShareClosed, CodeSessionExpired:
		return http.StatusGone
	case CodeProtocolUnsupported:
		return http.StatusUpgradeRequired
	case CodeBusy:
		return http.StatusTooManyRequests
	case CodeTargetUnreachable:
		return http.StatusBadGateway
	case CodeVPNUnavailable:
		return http.StatusServiceUnavailable
	case CodeDialTimeout:
		return http.StatusGatewayTimeout
	default:
		return http.StatusInternalServerError
	}
}

// CodeForStatus is the fallback when a response carries no usable body.
func CodeForStatus(status int) Code {
	switch status {
	case http.StatusBadRequest:
		return CodeInvalidRequest
	case http.StatusUnauthorized:
		return CodeInvalidCredentials
	case http.StatusForbidden:
		return CodeResourceDenied
	case http.StatusConflict:
		return CodeStaleResources
	case http.StatusGone:
		return CodeShareClosed
	case http.StatusUpgradeRequired:
		return CodeProtocolUnsupported
	case http.StatusTooManyRequests:
		return CodeBusy
	case http.StatusBadGateway:
		return CodeTargetUnreachable
	case http.StatusServiceUnavailable:
		return CodeVPNUnavailable
	case http.StatusGatewayTimeout:
		return CodeDialTimeout
	default:
		return CodeInvalidRequest
	}
}

// Terminal reports whether retrying the same request can never help. The client
// uses it to stop rather than loop: a closed share, a rejected fingerprint or an
// incompatible protocol is final.
func (c Code) Terminal() bool {
	switch c {
	case CodeShareClosed, CodeSessionExpired, CodeProtocolUnsupported, CodeInvalidCredentials, CodeResourceDenied, CodeDNSUnauthorized:
		return true
	}
	return false
}
