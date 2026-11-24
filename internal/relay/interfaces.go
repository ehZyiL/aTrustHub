package relay

import (
	"context"
	"net"
)

// Source is the sharing host's view of one bound access point. The vpn package
// implements it; the relay server only knows this narrow shape.
//
// A Source is pinned to one endpoint pointer, ID and generation at acquisition.
// It never follows a reconnect: the controller finishes the old instance and
// acquires a new Source for the same access point.
type Source interface {
	// Snapshot returns the current effective (TCP-published) rules, epoch and
	// revision. It must fail rather than return a widened guess.
	Snapshot(ctx context.Context) (SourceSnapshot, error)
	// DialVPN opens a strict connection through the bound VPN for revision.
	// direct, blocked and unknown targets are refused, never dialed locally.
	DialVPN(ctx context.Context, revision, target string) (net.Conn, error)
	// ExchangeDNS resolves inside the bound session. ok is false when the
	// source cannot answer internal DNS at all.
	ExchangeDNS(ctx context.Context, revision string, query []byte) ([]byte, error)
	// Changes coalesces resource changes. The consumer re-reads Snapshot; it
	// does not count edges.
	Changes() <-chan struct{}
	// Done closes when the bound session or endpoint generation is gone.
	Done() <-chan struct{}
	// Close releases the adapter. It never logs out the VPN.
	Close() error
}

// Sink is what the controller needs from the outside world: secrets, interface
// discovery and the bound source factory. Tests inject fakes.
type Sink interface {
	// AcquireSource binds one access point. It fails when the point is not a
	// live, strictly capable, locally hosted VPN session.
	AcquireSource(ctx context.Context, pointID string) (Source, error)
	// PointName is the display name of an access point.
	PointName(pointID string) string
	// PointExists reports whether the configuration still has the point.
	PointExists(pointID string) bool
}
