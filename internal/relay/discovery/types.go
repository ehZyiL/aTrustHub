// Package discovery publishes and browses 局域网分享 over DNS-SD / mDNS.
//
// It owns the wire format, the candidate cache and the publish/browse
// lifecycle, and nothing else: it never learns a token, a certificate, a VPN
// resource or a system setting. The package deliberately does not import its
// parent (internal/relay) so the controller can be wired to it without a cycle.
package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/ehzyil/connect-hub/internal/lanname"
	"github.com/ehzyil/connect-hub/internal/model"
)

// ServiceType is the DNS-SD service this feature registers. The underscore
// prefix and the ".local." suffix are the multicast DNS form.
const ServiceType = "_connecthub._tcp.local."

// DraftVersion is the discovery protocol version carried in the "dv" TXT key.
// It is independent of the share protocol version and of the worker IPC
// version; a peer that does not understand it is shown as incompatible.
const DraftVersion = 1

const (
	// MaxCandidates bounds the browser cache.
	MaxCandidates = 128
	// MaxAddressesPerInstance bounds how many IPv4 records one instance may add.
	MaxAddressesPerInstance = 8
	// MaxTXTBytes and MaxTXTFields bound one TXT record. DNS-SD asks for a TXT
	// record small enough to travel in a single packet; 1024 leaves room for
	// the escaping multicast DNS applies to non-ASCII bytes (a 160 byte name
	// can occupy three characters per byte on the wire).
	MaxTXTBytes  = 1024
	MaxTXTFields = 16
)

// Record time-to-live values follow RFC 6762 section 10: records that name a
// host (A, and SRV whose rdata is a host name) use 120s, everything else uses
// the 75 minute default. They are variables so tests can shorten them.
var (
	TTLHost  = 120 * time.Second
	TTLOther = 4500 * time.Second
)

// Interface is one local address the feature may use. Name is the operating
// system's interface name and is what the user picked in 使用网络.
type Interface struct {
	Name string
	IPv4 string
}

// Valid reports whether the interface is usable for discovery: a name and an
// RFC1918 IPv4 address. Discovery is v1 is IPv4-only by design.
func (i Interface) Valid() bool {
	if i.Name == "" || net.ParseIP(i.IPv4).To4() == nil {
		return false
	}
	return model.RFC1918(net.ParseIP(i.IPv4))
}

func (i Interface) String() string {
	if i.Name == "" {
		return i.IPv4
	}
	return i.Name + " (" + i.IPv4 + ")"
}

// Announcement is what a sharing host publishes. It carries no credential and
// no share code: a colleague learns an address and a name, never an
// authorization.
type Announcement struct {
	// Generation changes whenever the sharing instance changes, so a
	// registration that finishes late can be recognised and revoked.
	Generation uint64
	ShareID    string
	// Name is the public alias. Empty is resolved to the default alias before
	// validation, so a published announcement always has a valid name.
	Name            string
	ProtocolVersion int
	Interface       Interface
	// Address is the share listener's IPv4 address; Port is the port it
	// actually bound. Both describe a running instance only.
	Address string
	Port    int
}

// Validate checks everything that will travel on the wire. It is the publish
// boundary: a value that fails here is never broadcast.
func (a Announcement) Validate() error {
	if a.Generation == 0 {
		return errors.New("缺少发布代次")
	}
	if !model.ValidShareID(a.ShareID) {
		return errors.New("分享标识不合法")
	}
	if a.Name == "" {
		return errors.New("缺少公开名称")
	}
	if err := lanname.Valid(a.Name); err != nil {
		return err
	}
	if a.ProtocolVersion <= 0 {
		return errors.New("分享协议版本不合法")
	}
	if !a.Interface.Valid() {
		return fmt.Errorf("发现网卡不合法：%s", a.Interface)
	}
	if a.Address != "" && a.Address != a.Interface.IPv4 {
		// The advertised address must be the one on the interface we listen
		// on; anything else could point colleagues at a different network.
		return errors.New("分享地址与所选网卡不一致")
	}
	if a.Port < 1 || a.Port > 65535 {
		return errors.New("分享端口不合法")
	}
	return nil
}

// Candidate is one share a colleague can see. It is unverified: nothing here
// proves the remote identity, which is why joining still needs a share code.
type Candidate struct {
	Instance        string
	ShareID         string
	Name            string
	ProtocolVersion int
	DraftVersion    int
	Address         string
	Port            int
	Interface       string
	// ObservedAt is when the instance was first seen in this browsing session;
	// ExpiresAt is the earliest expiry of the records that make it usable.
	ObservedAt time.Time
	ExpiresAt  time.Time
}

// Key identifies one candidate endpoint. The instance name, the receiving
// interface, the address and the port all participate: two hosts that claim the
// same share ID are different endpoints, and neither may evict the other.
func (c Candidate) Key() string {
	return fmt.Sprintf("%s|%s|%s|%d", c.Instance, c.Interface, c.Address, c.Port)
}

// Compatible reports whether this build may act on the candidate. An unknown
// protocol version is shown but cannot be joined.
func (c Candidate) Compatible() bool {
	return c.DraftVersion == DraftVersion && c.ProtocolVersion == shareProtocolVersion
}

// shareProtocolVersion mirrors relay.ProtocolVersion. It is duplicated here
// because this package must not import its parent; protocol_test.go asserts the
// two stay equal.
const shareProtocolVersion = 1

// EventKind tells the browser cache what happened.
type EventKind string

const (
	EventAdded   EventKind = "added"
	EventUpdated EventKind = "updated"
	EventRemoved EventKind = "removed"
)

// Event is one cache transition produced by the assembler.
type Event struct {
	Kind      EventKind
	Candidate Candidate
}

// Snapshot is an immutable, ordered view for the UI. It is built on the
// browsing goroutine and handed over as a value, so the UI thread never shares
// mutable cache state.
type Snapshot struct {
	// Generation increments on every browse start or refresh; an older
	// snapshot must not be applied to a newer list.
	Generation uint64
	Candidates []Candidate
}

// StatusState is the publisher's user-visible state.
type StatusState string

const (
	StatusIdle      StatusState = "idle"
	StatusPending   StatusState = "pending"
	StatusPublished StatusState = "published"
	StatusFailed    StatusState = "failed"
)

// Status is what the panel shows. "Published" only means this host registered
// successfully; it never claims that a colleague received or reached it.
type Status struct {
	State   StatusState
	Message string
	// RetryAt is the next attempt after a failure.
	RetryAt time.Time
	// Generation is the announcement generation the status refers to.
	Generation uint64
}

// Registration is a live advertisement.
type Registration interface {
	// Close withdraws the announcement (a DNS-SD goodbye) and releases sockets.
	Close() error
}

// Session is one browsing session. Refresh re-queries without discarding the
// cache; Close ends it and releases sockets.
type Session interface {
	Refresh() error
	Close() error
}

// BrowseOptions configures one browsing session.
type BrowseOptions struct {
	// Interfaces is the exact set of local interfaces to browse on. An empty
	// set browses nothing: discovery never silently widens its scope.
	Interfaces []Interface
	// OnRecords receives the records of one packet, already attributed to the
	// interface they arrived on. It must not block: the backend calls it from
	// its receive loop.
	OnRecords func([]Record)
	// Logf records protocol-level problems without credentials.
	Logf func(string, ...any)
}

// Backend is the platform boundary. The production implementation speaks
// multicast DNS with net sockets; tests use an in-memory one.
type Backend interface {
	Advertise(ctx context.Context, a Announcement) (Registration, error)
	Browse(ctx context.Context, opts BrowseOptions) (Session, error)
}
