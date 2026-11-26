package relay

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	contract "github.com/ehzyil/connect-hub/internal/relay/contract"
)

// readBounded reads at most max bytes and reports whether the body was longer.
func readBounded(r io.Reader, max int64) ([]byte, error) {
	if r == nil {
		return nil, nil
	}
	data, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, NewError(CodeInvalidRequest, "请求体超过上限")
	}
	return data, nil
}

// decodeStrictJSON decodes one JSON value from a bounded body and refuses
// trailing content, so a proxy cannot smuggle a second document.
func decodeStrictJSON(data []byte, out any) error {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return NewError(CodeInvalidRequest, "请求体不是有效的 JSON：%v", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return NewError(CodeInvalidRequest, "请求体包含尾随内容")
	}
	return nil
}

// bearerToken extracts the token from an Authorization header. The token never
// travels in a path, query or log line.
func bearerToken(header string) (string, error) {
	value := strings.TrimSpace(header)
	const prefix = "bearer "
	if len(value) <= len(prefix) || !strings.EqualFold(value[:len(prefix)], prefix) {
		return "", NewError(CodeInvalidCredentials, "缺少分享凭据")
	}
	token := strings.TrimSpace(value[len(prefix):])
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		return "", NewError(CodeInvalidCredentials, "分享凭据格式无效")
	}
	return token, nil
}

// validRequestID bounds a diagnostic correlation id.
func validRequestID(id string) bool {
	if len(id) > MaxRequestIDBytes {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') && r != '-' && r != '_' {
			return false
		}
	}
	return true
}

// validClientID bounds a client instance id.
func validClientID(id string) bool {
	if id == "" || len(id) > MaxClientIDBytes {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') && r != '-' && r != '_' {
			return false
		}
	}
	return true
}

// sanitizeClientName trims a display name to a bounded rune count and drops
// control characters, so a client cannot poison the host's UI or logs.
func sanitizeClientName(name string) string {
	name = strings.TrimSpace(name)
	var b strings.Builder
	count := 0
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			continue
		}
		if count >= MaxClientNameRunes {
			break
		}
		b.WriteRune(r)
		count++
	}
	return b.String()
}

// writeError emits the bounded JSON error contract.
func writeError(w http.ResponseWriter, err error) {
	var re *Error
	if !errors.As(err, &re) {
		re = NewError(CodeInvalidRequest, "%v", err)
	}
	status := re.HTTPStatus()
	body := struct {
		Code      Code   `json:"code"`
		Message   string `json:"message"`
		Retryable bool   `json:"retryable"`
		RequestID string `json:"requestId,omitempty"`
	}{re.Code, re.Message, re.Retryable, re.RequestID}
	data, mErr := json.Marshal(body)
	if mErr != nil || len(data) > MaxErrorBody {
		data = []byte(`{"code":"invalid_request","message":"请求失败","retryable":false}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

// randomShareID returns a fresh share identity.
func randomShareID() (string, error) {
	b := make([]byte, shareIDLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// randomShareToken returns a fresh share token.
func randomShareToken() (string, error) {
	b := make([]byte, shareTokenLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

const ProtocolVersion = contract.ProtocolVersion

const HeaderAuthorization = contract.HeaderAuthorization

const HeaderProtocol = contract.HeaderProtocol

const HeaderShareID = contract.HeaderShareID

const HeaderRequestID = contract.HeaderRequestID

const HeaderShareEpoch = contract.HeaderShareEpoch

const HeaderResourceRev = contract.HeaderResourceRev

const HeaderRetryAfter = contract.HeaderRetryAfter

const HeaderIfNoneMatch = contract.HeaderIfNoneMatch

const HeaderETag = contract.HeaderETag

const ALPNProtocol = contract.ALPNProtocol

const DNSMediaType = contract.DNSMediaType

const TLSHandshakeTimeout = contract.TLSHandshakeTimeout

const ControlTimeout = contract.ControlTimeout

const FirstConnectBudget = contract.FirstConnectBudget

const DialTimeout = contract.DialTimeout

const HeartbeatInterval = contract.HeartbeatInterval

const ClientLease = contract.ClientLease

const CleanupBudget = contract.CleanupBudget

const CertificateLifetime = contract.CertificateLifetime

const MaxHeaderBytes = contract.MaxHeaderBytes

const MaxErrorBody = contract.MaxErrorBody

const MaxSessionBody = contract.MaxSessionBody

const MaxDNSBody = contract.MaxDNSBody

const MaxActiveClients = contract.MaxActiveClients

const MaxUnauthenticated = contract.MaxUnauthenticated

const MaxBusinessConnsTotal = contract.MaxBusinessConnsTotal

const MaxBusinessConnsEach = contract.MaxBusinessConnsEach

const MaxDNSConcurrentTotal = contract.MaxDNSConcurrentTotal

const MaxDNSConcurrentEach = contract.MaxDNSConcurrentEach

const AuthRatePerIP = contract.AuthRatePerIP

const AuthBurstPerIP = contract.AuthBurstPerIP

const AuthRateGlobal = contract.AuthRateGlobal

const AuthBurstGlobal = contract.AuthBurstGlobal

const MaxRequestIDBytes = contract.MaxRequestIDBytes

const MaxClientIDBytes = contract.MaxClientIDBytes

const MaxClientNameRunes = contract.MaxClientNameRunes

const CapStrictTCP = contract.CapStrictTCP

const CapInternalDNS = contract.CapInternalDNS

type Capabilities = contract.Capabilities

type SessionRequest = contract.SessionRequest

type SessionResponse = contract.SessionResponse

type StatusResponse = contract.StatusResponse

type ResourcesResponse = contract.ResourcesResponse

type SourceSnapshot = contract.SourceSnapshot
