// Package client is the desktop-facing share control boundary. It depends only
// on contracts; the application injects the current in-process implementation.
package client

import (
	"context"
	"errors"

	"github.com/ehzyil/connect-hub/internal/components"
	"github.com/ehzyil/connect-hub/internal/relay/contract"
)

type Share interface {
	View() contract.View
	Settings() contract.Settings
	DiscoverySnapshot() (contract.DiscoveryAnnouncement, bool)
	ShareCode() (string, error)
	Enable(context.Context, contract.EnableOptions) error
	Restore(context.Context) error
	Disable(context.Context) error
	CancelEnable(context.Context) error
	Suspend(context.Context) error
	Shutdown(context.Context) error
	Retry(context.Context) error
	RetryPersistDisable() error
	SetDiscovery(bool, string) error
	Wake()
}

type Controller interface {
	Share
	contract.PairControl
	PauseSharing(context.Context) error
	ResumeSharing(context.Context) error
	Component() components.Snapshot
}

// Control separates availability from business state. A nil implementation is
// explicitly unavailable and never replaced by another VPN login mechanism.
type Control struct {
	Share
	instance     string
	availability components.Availability
	detail       string
}

func (c *Control) PairControl(ctx context.Context, cmd contract.PairCommand) (contract.PairView, error) {
	if p, ok := c.Share.(contract.PairControl); ok {
		return p.PairControl(ctx, cmd)
	}
	return contract.PairView{}, errors.New("pairing_unsupported: 分享组件不支持设备配对")
}
func (c *Control) PauseSharing(ctx context.Context) error {
	if p, ok := c.Share.(interface{ PauseSharing(context.Context) error }); ok {
		return p.PauseSharing(ctx)
	}
	return errors.New("分享组件不支持暂停")
}
func (c *Control) ResumeSharing(ctx context.Context) error {
	if p, ok := c.Share.(interface{ ResumeSharing(context.Context) error }); ok {
		return p.ResumeSharing(ctx)
	}
	return errors.New("分享组件不支持恢复")
}

func NewLocal(share Share) *Control {
	id, err := components.NewID()
	if err != nil {
		return Unavailable(err.Error())
	}
	if share == nil {
		return Unavailable("分享组件不可用")
	}
	return &Control{Share: share, instance: id, availability: components.Ready}
}

func Unavailable(detail string) *Control {
	if detail == "" {
		detail = "分享组件不可用"
	}
	if len(detail) > components.MaxDetailBytes {
		detail = detail[:components.MaxDetailBytes]
	}
	return &Control{Share: unavailable{detail: detail}, availability: components.Missing, detail: detail}
}

func (c *Control) Component() components.Snapshot {
	state := components.Disabled
	v := c.View()
	switch v.State {
	case contract.StateStarting:
		state = components.Starting
	case contract.StateRunning:
		state = components.Running
	case contract.StateWaiting:
		state = components.Waiting
	case contract.StateStopping:
		state = components.Stopping
	case contract.StateBlocked, contract.StateCleanupPending:
		state = components.Failed
	}
	if v.State == contract.StateOff && v.Failure != "" && c.availability == components.Ready {
		state = components.Failed
	}
	detail := c.detail
	if detail == "" {
		detail = v.Failure
	}
	if len(detail) > components.MaxDetailBytes {
		detail = detail[:components.MaxDetailBytes]
	}
	return components.Snapshot{Availability: c.availability, State: state, InstanceID: c.instance, Detail: detail}
}

type unavailable struct{ detail string }

func (u unavailable) View() contract.View {
	return contract.View{State: contract.StateOff, Failure: u.detail, FailureCode: "unavailable"}
}
func (u unavailable) Settings() contract.Settings { return contract.Settings{} }
func (u unavailable) DiscoverySnapshot() (contract.DiscoveryAnnouncement, bool) {
	return contract.DiscoveryAnnouncement{}, false
}
func (u unavailable) ShareCode() (string, error) { return "", errors.New(u.detail) }
func (u unavailable) Enable(context.Context, contract.EnableOptions) error {
	return errors.New(u.detail)
}
func (u unavailable) Restore(context.Context) error      { return errors.New(u.detail) }
func (u unavailable) Disable(context.Context) error      { return errors.New(u.detail) }
func (u unavailable) CancelEnable(context.Context) error { return nil }
func (u unavailable) Suspend(context.Context) error      { return nil }
func (u unavailable) Shutdown(context.Context) error     { return nil }
func (u unavailable) Retry(context.Context) error        { return errors.New(u.detail) }
func (u unavailable) RetryPersistDisable() error         { return errors.New(u.detail) }
func (u unavailable) SetDiscovery(bool, string) error    { return errors.New(u.detail) }
func (u unavailable) Wake()                              {}
