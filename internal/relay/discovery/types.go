package discovery

import (
	"context"
	discoverycontract "github.com/ehzyil/connect-hub/internal/relay/discovery/contract"
	"time"
)

// Record time-to-live values follow RFC 6762 section 10: records that name a
// host (A, and SRV whose rdata is a host name) use 120s, everything else uses
// the 75 minute default. They are variables so tests can shorten them.
var (
	TTLHost  = 120 * time.Second
	TTLOther = 4500 * time.Second
)

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

const ServiceType = discoverycontract.ServiceType

const DraftVersion = discoverycontract.DraftVersion

const MaxCandidates = discoverycontract.MaxCandidates

const MaxAddressesPerInstance = discoverycontract.MaxAddressesPerInstance

const MaxTXTBytes = discoverycontract.MaxTXTBytes

const MaxTXTFields = discoverycontract.MaxTXTFields

type Interface = discoverycontract.Interface

type Announcement = discoverycontract.Announcement

type Candidate = discoverycontract.Candidate

type EventKind = discoverycontract.EventKind

const EventAdded = discoverycontract.EventAdded

const EventUpdated = discoverycontract.EventUpdated

const EventRemoved = discoverycontract.EventRemoved

type Event = discoverycontract.Event

type Snapshot = discoverycontract.Snapshot

type StatusState = discoverycontract.StatusState

const StatusIdle = discoverycontract.StatusIdle

const StatusPending = discoverycontract.StatusPending

const StatusPublished = discoverycontract.StatusPublished

const StatusFailed = discoverycontract.StatusFailed

type Status = discoverycontract.Status
