package contract

import (
	"sort"
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
