package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"sort"
	"sync"
	"time"

	"github.com/bytemare/opaque"
	"github.com/ehzyil/connect-hub/internal/relay/contract"
)

type pairRecord struct {
	invite *invitationRecord
	view   contract.PairRequest
	pub    ed25519.PublicKey
	key    []byte
}

type invitationRecord struct {
	view     contract.Invitation
	material *opaque.ServerKeyMaterial
	record   *opaque.ClientRecord
}

type pairingState struct {
	mu          sync.Mutex
	store       contract.DeviceStore
	shareID     string
	fingerprint string
	invite      *invitationRecord
	requests    map[string]*pairRecord
	devices     map[string]contract.PairedDevice
	denied      map[string]bool
	// An uncertain storage result freezes mutations. Retrying the exact same
	// candidate reconciles the durable state before another operation can run.
	pending      []contract.PairedDevice
	pendingApply func()
	now          func() time.Time
	onRevoke     func(string)
	available    bool
}

func newPairingState(ctx context.Context, store contract.DeviceStore, shareID, fp string, revoke func(string)) (*pairingState, error) {
	p := &pairingState{store: store, shareID: shareID, fingerprint: fp, requests: map[string]*pairRecord{}, devices: map[string]contract.PairedDevice{}, denied: map[string]bool{}, now: time.Now, onRevoke: revoke, available: store != nil}
	if store == nil {
		return p, nil
	}
	devices, err := store.LoadDevices(ctx, shareID)
	if err != nil {
		return nil, errors.New("设备授权无法读取，已停止共享")
	}
	if len(devices) > contract.MaxPairedDevices {
		return nil, errors.New("设备授权超过上限")
	}
	for _, d := range devices {
		if len(d.PublicKey) != ed25519.PublicKeySize || deviceID(d.PublicKey) != d.ID || p.devices[d.ID].ID != "" {
			return nil, errors.New("设备授权记录无效")
		}
		d.PublicKey = append([]byte(nil), d.PublicKey...)
		p.devices[d.ID] = d
	}
	return p, nil
}

func deviceID(pub []byte) string { sum := sha256.Sum256(pub); return hex.EncodeToString(sum[:]) }

func randomPIN() (string, error) {
	out := make([]byte, contract.InviteDigits)
	for i := range out {
		n, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", err
		}
		out[i] = '0' + byte(n.Int64())
	}
	return string(out), nil
}

func (p *pairingState) expireLocked() {
	for id, r := range p.requests {
		if !p.now().Before(r.view.ExpiresAt) {
			r.view.State = "expired"
			if !p.now().Before(r.view.ExpiresAt.Add(time.Minute)) {
				delete(p.requests, id)
			}
		}
	}
}

func (p *pairingState) snapshotLocked() contract.PairView {
	p.expireLocked()
	v := contract.PairView{}
	if p.invite != nil {
		i := p.invite.view
		v.Invitation = &i
	}
	for _, r := range p.requests {
		v.Requests = append(v.Requests, r.view)
	}
	for _, d := range p.devices {
		d.PublicKey = append([]byte(nil), d.PublicKey...)
		v.Devices = append(v.Devices, d)
	}
	sort.Slice(v.Requests, func(i, j int) bool { return v.Requests[i].ID < v.Requests[j].ID })
	sort.Slice(v.Devices, func(i, j int) bool { return v.Devices[i].ID < v.Devices[j].ID })
	return v
}

func (p *pairingState) activeInviteLocked() bool {
	return p.available && p.invite != nil && !p.invite.view.Cancelled && p.now().Before(p.invite.view.ExpiresAt) && p.invite.view.Approved < p.invite.view.Capacity
}

func (p *pairingState) flushLocked(ctx context.Context) error {
	if p.pendingApply == nil {
		return nil
	}
	if err := p.store.SaveDevices(ctx, p.shareID, p.pending); err != nil {
		return errors.New("persist: 设备授权未确认保存，请重试同一操作")
	}
	p.devices = map[string]contract.PairedDevice{}
	for _, d := range p.pending {
		p.devices[d.ID] = d
	}
	apply := p.pendingApply
	p.pendingApply = nil
	p.pending = nil
	apply()
	return nil
}

func (p *pairingState) commitLocked(ctx context.Context, devices map[string]contract.PairedDevice, apply func()) error {
	p.pending = make([]contract.PairedDevice, 0, len(devices))
	for _, d := range devices {
		p.pending = append(p.pending, d)
	}
	p.pendingApply = apply
	return p.flushLocked(ctx)
}

func (p *pairingState) control(ctx context.Context, c contract.PairCommand) (contract.PairView, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.available {
		return contract.PairView{}, errors.New("pairing_unsupported: 组件未提供配对存储")
	}
	if err := p.flushLocked(ctx); err != nil {
		return p.snapshotLocked(), err
	}
	p.expireLocked()
	switch c.Operation {
	case "list":
	case "create":
		pin, err := randomPIN()
		if err != nil {
			return contract.PairView{}, err
		}
		inv, err := newInvitation(pin, p.shareID, p.fingerprint, p.now())
		if err != nil {
			return contract.PairView{}, err
		}
		p.invite = inv
		v := p.snapshotLocked()
		v.PIN = pin
		return v, nil
	case "cancel":
		if p.invite != nil {
			p.invite.view.Cancelled = true
		}
	case "approve":
		r := p.requests[c.ID]
		if r == nil {
			return p.snapshotLocked(), errors.New("request_expired: 配对请求已超时")
		}
		if r.view.State == "expired" {
			return p.snapshotLocked(), errors.New("request_expired: 配对请求已超时")
		}
		if r.view.State == "approved" || r.view.State == "claimed" {
			return p.snapshotLocked(), nil
		}
		if r.view.State != "pending" {
			return p.snapshotLocked(), errors.New("request_rejected: 请求不可批准")
		}
		if d := p.devices[r.view.DeviceID]; d.ID != "" {
			r.view.State = "approved"
			return p.snapshotLocked(), nil
		}
		// Cancelling/expiring an invitation blocks new handshakes. A request
		// already authenticated may still be approved before its own deadline.
		if r.invite == nil || r.invite.view.Approved >= r.invite.view.Capacity {
			return p.snapshotLocked(), errors.New("invite_exhausted: 邀请名额已用完")
		}
		if len(p.devices) >= contract.MaxPairedDevices {
			return p.snapshotLocked(), errors.New("device_limit: 已配对设备达到上限")
		}
		d := contract.PairedDevice{ID: r.view.DeviceID, PublicKey: append([]byte(nil), r.pub...), Name: r.view.Name, ApprovedAt: p.now(), RequestID: r.view.ID}
		devices := p.copyDevicesLocked()
		devices[d.ID] = d
		invite := r.invite
		if err := p.commitLocked(ctx, devices, func() { r.view.State = "approved"; invite.view.Approved++; delete(p.denied, d.ID) }); err != nil {
			return p.snapshotLocked(), err
		}
	case "reject":
		if r := p.requests[c.ID]; r != nil && r.view.State == "pending" {
			r.view.State = "rejected"
		}
	case "revoke":
		if p.devices[c.ID].ID == "" {
			return p.snapshotLocked(), nil
		}
		// Immediately deny new and existing leases, even if disk persistence
		// subsequently fails. The uncertain transaction blocks reauthorization.
		p.onRevoke(c.ID)
		p.denied[c.ID] = true
		devices := p.copyDevicesLocked()
		delete(devices, c.ID)
		if err := p.commitLocked(ctx, devices, func() {
			for _, r := range p.requests {
				if r.view.DeviceID == c.ID {
					r.view.State = "revoked"
				}
			}
		}); err != nil {
			return p.snapshotLocked(), err
		}
	case "revoke-all":
		for id := range p.devices {
			p.denied[id] = true
			p.onRevoke(id)
		}
		if p.invite != nil {
			p.invite.view.Cancelled = true
		}
		if err := p.commitLocked(ctx, map[string]contract.PairedDevice{}, func() {
			for _, r := range p.requests {
				r.view.State = "revoked"
			}
		}); err != nil {
			return p.snapshotLocked(), err
		}
	default:
		return contract.PairView{}, errors.New("invalid_request: 未知配对操作")
	}
	return p.snapshotLocked(), nil
}

func (p *pairingState) copyDevicesLocked() map[string]contract.PairedDevice {
	out := make(map[string]contract.PairedDevice, len(p.devices))
	for id, d := range p.devices {
		out[id] = d
	}
	return out
}

func (s *Server) PairControl(ctx context.Context, c contract.PairCommand) (contract.PairView, error) {
	return s.pairing.control(ctx, c)
}
