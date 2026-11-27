package contract

import (
	"context"
	"time"
)

// Pairing policy is independent of online leases and business tunnel limits.
const (
	InviteDigits          = 8
	InviteLifetime        = 5 * time.Minute
	InviteCapacity        = 5
	PairRequestLifetime   = 5 * time.Minute
	MaxPairRequests       = 16
	MaxPairedDevices      = 128
	MaxPairHandshakes     = 8
	PairHandshakeLifetime = 20 * time.Second
	PairPollInterval      = 200 * time.Millisecond
	PairRatePerIP         = 6
	PairBurstPerIP        = InviteCapacity
	PairRateGlobal        = 60
	PairBurstGlobal       = 12
	PairCapability        = "opaque-ed25519-v2"
)

type Invitation struct {
	ID        string
	ExpiresAt time.Time
	Capacity  int
	Approved  int
	Cancelled bool
}

type PairRequest struct {
	ID           string
	DeviceID     string
	Name         string
	Source       string
	Verification string
	State        string
	ExpiresAt    time.Time
}

// PairedDevice contains a verification key only. No bearer secret is issued.
type PairedDevice struct {
	ID         string
	PublicKey  []byte
	Name       string
	ApprovedAt time.Time
	RequestID  string
}

// DeviceStore must durably and atomically replace the complete bounded record.
// A failed write must never be reported as a successful approval.
type DeviceStore interface {
	LoadDevices(context.Context, string) ([]PairedDevice, error)
	SaveDevices(context.Context, string, []PairedDevice) error
}

type PairCommand struct {
	Operation string
	ID        string
}

// PIN appears only in the response to an explicit local create operation.
// Snapshots and network advertisements never contain it.
type PairView struct {
	Invitation *Invitation
	PIN        string `json:",omitempty"`
	Requests   []PairRequest
	Devices    []PairedDevice
}

type PairControl interface {
	PairControl(context.Context, PairCommand) (PairView, error)
}

type PairTarget struct {
	HostName string
	Host     string
	Port     int
	ShareID  string
	Name     string
}

type PairProgress struct {
	Request PairRequest
	Code    *ShareCode `json:",omitempty"`
	Error   string     `json:",omitempty"`
}

type PairAttempt interface {
	Updates() <-chan PairProgress
	Stored(context.Context) error
	Ack(context.Context) error
	Close() error
}
