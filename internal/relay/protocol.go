package relay

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// ProtocolVersion is the LAN v1 major version. It is independent of the worker
// IPC version and of the configuration format version.
const ProtocolVersion = 1

// Request headers of the LAN v1 protocol.
const (
	HeaderAuthorization = "Authorization"
	HeaderProtocol      = "Hub-Protocol"
	HeaderShareID       = "Hub-Share-ID"
	HeaderRequestID     = "Hub-Request-ID"
	HeaderShareEpoch    = "Hub-Share-Epoch"
	HeaderResourceRev   = "Hub-Resource-Revision"
	HeaderRetryAfter    = "Retry-After"
	HeaderIfNoneMatch   = "If-None-Match"
	HeaderETag          = "ETag"
)

// ALPNProtocol is the only negotiated application protocol. v1 stays on
// HTTP/1.1 so CONNECT + Hijack has one well-defined behaviour.
const ALPNProtocol = "http/1.1"

// DNSMediaType is the body type of the DNS query endpoint.
const DNSMediaType = "application/dns-message"

// First-version defaults. They are starting values to be calibrated on real
// hardware, not measured acceptance results.
const (
	TLSHandshakeTimeout   = 5 * time.Second
	ControlTimeout        = 3 * time.Second
	FirstConnectBudget    = 12 * time.Second
	DialTimeout           = 5 * time.Second
	HeartbeatInterval     = 5 * time.Second
	ClientLease           = 15 * time.Second
	CleanupBudget         = 3 * time.Second
	CertificateLifetime   = 365 * 24 * time.Hour
	MaxHeaderBytes        = 16 << 10
	MaxErrorBody          = 4 << 10
	MaxSessionBody        = 4 << 10
	MaxDNSBody            = 4 << 10
	MaxActiveClients      = 10
	MaxUnauthenticated    = 32
	MaxBusinessConnsTotal = 256
	MaxBusinessConnsEach  = 64
	MaxDNSConcurrentTotal = 16
	MaxDNSConcurrentEach  = 4
	// AuthRatePerIP and AuthRateGlobal bound failed authentication. They are
	// protocol defaults, not tuned numbers.
	AuthRatePerIP      = 10
	AuthBurstPerIP     = 5
	AuthRateGlobal     = 60
	AuthBurstGlobal    = 10
	MaxRequestIDBytes  = 64
	MaxClientIDBytes   = 64
	MaxClientNameRunes = 40
)

// Capability names. v1 can only promise strict TCP; internal DNS is declared
// only when the bound source really offers it.
const (
	CapStrictTCP   = "strict_tcp_v1"
	CapInternalDNS = "internal_dns_v1"
)

// Capabilities is the fixed v1 capability set.
type Capabilities struct {
	StrictTCP   bool `json:"strictTcp"`
	InternalDNS bool `json:"internalDns"`
}

// Names returns the stable sorted names, for revision hashing.
func (c Capabilities) Names() []string {
	out := make([]string, 0, 2)
	if c.StrictTCP {
		out = append(out, CapStrictTCP)
	}
	if c.InternalDNS {
		out = append(out, CapInternalDNS)
	}
	sort.Strings(out)
	return out
}

// Validate refuses a capability set v1 cannot enforce. Unknown capabilities are
// simply not representable, so they can never turn into authorization.
func (c Capabilities) Validate() error {
	if !c.StrictTCP {
		return NewError(CodeProtocolUnsupported, "分享主机没有声明严格 TCP 能力")
	}
	return nil
}

// SessionRequest is the body of POST /v1/sessions. It carries only a random
// client instance id and an optional display name: no system user name, no
// hardware identity and no authorization.
type SessionRequest struct {
	ClientID string `json:"clientId"`
	Name     string `json:"name,omitempty"`
}

// SessionResponse is what a successful session creation returns.
type SessionResponse struct {
	Version          int               `json:"version"`
	ShareID          string            `json:"shareId"`
	ServerInstanceID string            `json:"serverInstanceId"`
	ClientID         string            `json:"clientId"`
	ClientToken      string            `json:"clientToken"`
	Epoch            uint64            `json:"epoch"`
	Revision         string            `json:"revision"`
	Capabilities     Capabilities      `json:"capabilities"`
	LeaseSeconds     int               `json:"leaseSeconds"`
	Resources        *ResourceSnapshot `json:"resources"`
}

// StatusResponse is the effective share state plus this client's lease.
type StatusResponse struct {
	Version          int          `json:"version"`
	ShareID          string       `json:"shareId"`
	ServerInstanceID string       `json:"serverInstanceId"`
	Epoch            uint64       `json:"epoch"`
	Revision         string       `json:"revision"`
	LeaseSeconds     int          `json:"leaseSeconds"`
	RemainingSeconds int          `json:"remainingSeconds"`
	Capabilities     Capabilities `json:"capabilities"`
	Clients          int          `json:"clients"`
}

// ResourcesResponse is a complete snapshot, never an unbounded delta.
type ResourcesResponse struct {
	Version   int               `json:"version"`
	Epoch     uint64            `json:"epoch"`
	Revision  string            `json:"revision"`
	Resources *ResourceSnapshot `json:"resources"`
}

// DNSRequest is one bounded DNS question for the share's source.
type DNSRequest struct {
	Epoch    uint64 `json:"epoch"`
	Revision string `json:"revision"`
	Query    []byte `json:"query"`
}

// SourceSnapshot is what the sharing host may publish at one moment: the epoch,
// the effective revision and the rules behind them.
type SourceSnapshot struct {
	Epoch        uint64
	Revision     string
	Resources    *ResourceSnapshot
	Capabilities Capabilities
}

// Validate checks a snapshot before it is served or accepted.
func (s SourceSnapshot) Validate() error {
	if s.Resources == nil {
		return NewError(CodeVPNUnavailable, "分享源没有可发布的资源")
	}
	if err := s.Resources.Validate(); err != nil {
		return err
	}
	if s.Revision == "" {
		return NewError(CodeInvalidRequest, "分享源缺少资源版本")
	}
	return s.Capabilities.Validate()
}

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
