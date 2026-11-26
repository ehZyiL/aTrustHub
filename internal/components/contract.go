// Package components defines the bounded local control contract shared by
// optional components. LAN traffic and VPN worker IPC keep their own versions.
package components

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	Version         = 1
	MaxMessageBytes = 64 << 10
	MaxDetailBytes  = 4 << 10
	MaxCapabilities = 16
	MaxIDBytes      = 64
	DefaultTimeout  = 15 * time.Second
)

type Availability string

const (
	Missing      Availability = "missing"
	Incompatible Availability = "incompatible"
	Ready        Availability = "ready"
)

type State string

const (
	Disabled State = "disabled"
	Starting State = "starting"
	Waiting  State = "waiting"
	Running  State = "running"
	Stopping State = "stopping"
	Failed   State = "failed"
)

// Snapshot separates installation/compatibility from user intent and work.
type Snapshot struct {
	Availability Availability `json:"availability"`
	State        State        `json:"state"`
	InstanceID   string       `json:"instanceId,omitempty"`
	Detail       string       `json:"detail,omitempty"`
}

// Hello must succeed before the first operation. Capability names are exact,
// bounded strings; an unknown major version never silently falls back.
type Hello struct {
	Version      int      `json:"version"`
	InstanceID   string   `json:"instanceId"`
	Capabilities []string `json:"capabilities"`
}

func NewID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(id[:]), nil
}

func ValidID(id string) bool {
	if len(id) == 0 || len(id) > MaxIDBytes {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

func (h Hello) Check(required ...string) error {
	if h.Version != Version {
		return fmt.Errorf("组件协议版本不兼容：%d（需要 %d）", h.Version, Version)
	}
	if !ValidID(h.InstanceID) || len(h.Capabilities) > MaxCapabilities {
		return errors.New("组件握手无效")
	}
	capabilities := make(map[string]bool, len(h.Capabilities))
	for _, capability := range h.Capabilities {
		if !ValidID(capability) || capabilities[capability] {
			return errors.New("组件能力声明无效")
		}
		capabilities[capability] = true
	}
	for _, capability := range required {
		if !capabilities[capability] {
			return fmt.Errorf("组件缺少能力：%s", capability)
		}
	}
	return nil
}

// Request identifies one operation and its deadline. Cancellation uses the same
// instance/request IDs; receipt is not completion. Mutations stop only at a
// recoverable checkpoint and report a final Event before process exit.
type Request struct {
	Version    int       `json:"version"`
	InstanceID string    `json:"instanceId"`
	RequestID  string    `json:"requestId"`
	Operation  string    `json:"operation"`
	Deadline   time.Time `json:"deadline"`
}

func (r Request) Check(now time.Time) error {
	if r.Version != Version || !ValidID(r.InstanceID) || !ValidID(r.RequestID) || !ValidID(r.Operation) {
		return errors.New("组件请求无效")
	}
	if r.Deadline.IsZero() || !r.Deadline.After(now) {
		return errors.New("组件请求已超时")
	}
	return nil
}

// Event is bounded and ordered within one request. Payloads belong to the
// component-specific contract, not executable commands or unbounded log text.
type Event struct {
	Version    int             `json:"version"`
	InstanceID string          `json:"instanceId"`
	RequestID  string          `json:"requestId"`
	Sequence   uint64          `json:"sequence"`
	State      State           `json:"state"`
	Final      bool            `json:"final,omitempty"`
	Detail     string          `json:"detail,omitempty"`
	Payload    json.RawMessage `json:"payload,omitempty"`
}

func (e Event) Check() error {
	if e.Version != Version || !ValidID(e.InstanceID) || !ValidID(e.RequestID) || e.Sequence == 0 || len(e.Detail) > MaxDetailBytes {
		return errors.New("组件事件无效")
	}
	switch e.State {
	case Disabled, Starting, Waiting, Running, Stopping, Failed:
	default:
		return errors.New("未知组件状态")
	}
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if len(data) > MaxMessageBytes {
		return errors.New("组件消息超过上限")
	}
	return nil
}

// Cursor is owned by one consumer (e.g. the UI thread). Reset it when a new
// task starts; late instances, requests, duplicate events and post-final data
// are refused before updating the displayed snapshot.
type Cursor struct {
	InstanceID, RequestID string
	Sequence              uint64
	Final                 bool
}

func (c *Cursor) Accept(e Event) bool {
	if e.Check() != nil || c.Final || e.InstanceID != c.InstanceID || e.RequestID != c.RequestID || e.Sequence <= c.Sequence {
		return false
	}
	c.Sequence, c.Final = e.Sequence, e.Final
	return true
}

// Decode accepts exactly one bounded document, with no unknown fields.
func Decode(r io.Reader, out any) error {
	data, err := io.ReadAll(io.LimitReader(r, MaxMessageBytes+1))
	if err != nil {
		return err
	}
	if len(data) > MaxMessageBytes {
		return errors.New("组件消息超过上限")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return errors.New("组件消息包含尾随数据")
	}
	return nil
}
