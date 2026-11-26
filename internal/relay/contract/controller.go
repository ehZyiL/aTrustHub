package contract

import (
	"time"
)

// State is the share lifecycle. Enabled (a persisted user intent) and State (a
// runtime fact) are deliberately separate: Enabled can be Waiting, Starting,
// Running or Blocked.
type State string

const (
	StateOff            State = "off"
	StateWaiting        State = "waiting"
	StateStarting       State = "starting"
	StateRunning        State = "running"
	StateBlocked        State = "blocked"
	StateStopping       State = "stopping"
	StateCleanupPending State = "cleanup_pending"
)

// Settings is the persisted share intent and identity, mirrored from
// model.LANShareSettings by the persistence adapter.
type Settings struct {
	Enabled       bool
	PointID       string
	InterfaceName string
	PreferredIPv4 string
	Port          int
	BoundPort     int
	ShareID       string
	Fingerprint   string
	// DiscoveryEnabled is nil until the user makes a choice, exactly like the
	// persisted field. A nil value never announces anything.
	DiscoveryEnabled *bool
	DiscoveryName    string
}

// Clone copies the settings so callers can never mutate the controller through
// a shared pointer.
func (s Settings) Clone() Settings {
	if s.DiscoveryEnabled != nil {
		enabled := *s.DiscoveryEnabled
		s.DiscoveryEnabled = &enabled
	}
	return s
}

// Persistence keeps the intent in the configuration and the long-lived secrets
// in the credential store. It never stores Running.
type Persistence interface {
	ShareSettings() Settings
	SaveShareSettings(Settings) error
	GetSecret(key string) (string, error)
	SetSecret(key, value string) error
	DeleteSecret(key string) error
}

// ShareTokenKey is the secret-store key of a share's bearer token.
func ShareTokenKey(shareID string) string { return "lan-share:" + shareID + ":token" }

// Interface is one usable LAN address.
type Interface struct {
	Name string
	IPv4 string
}

// NetworkProvider enumerates the addresses a share may bind. The production
// implementation returns only up, non-loopback RFC1918 IPv4 addresses.
type NetworkProvider interface {
	LANCandidates() []Interface
}

// EnableOptions is what the user chose in the panel. There is no resource
// selection: the whole access point is shared.
type EnableOptions struct {
	PointID       string
	InterfaceName string
	PreferredIPv4 string
	Port          int
	// Discovery is the checkbox of the enable form, an explicit choice saved
	// together with the rest of the intent. DiscoveryName may be empty, in
	// which case the default alias derived from the share ID applies.
	Discovery     bool
	DiscoveryName string
}

// View is an immutable snapshot for the UI. It carries no token.
type View struct {
	Enabled     bool
	State       State
	Operation   uint64
	PointID     string
	PointName   string
	Interface   string
	Address     string
	Port        int
	Clients     int
	StartedAt   time.Time
	CertExpiry  time.Time
	Failure     string
	FailureCode string
	// CleanupPending means Stop could not finish in its budget; the instance
	// is still not restarted.
	CleanupPending bool
	// DiscoveryEnabled is the persisted preference; DiscoveryName is the
	// public alias the user chose (empty means "use the default").
	DiscoveryEnabled bool
	DiscoveryName    string
}

// DiscoveryAnnouncement is the credential-free snapshot the discovery publisher
// broadcasts. It only exists while the share is Running, so a waiting or
// blocked instance never advertises an endpoint that cannot be used, and it
// cannot carry a token: the code that builds it has no access to one.
type DiscoveryAnnouncement struct {
	// Generation changes whenever the share instance changes. A registration
	// that finishes after a generation change is revoked instead of published.
	Generation      uint64
	ShareID         string
	Name            string
	ProtocolVersion int
	InterfaceName   string
	Address         string
	Port            int
}
