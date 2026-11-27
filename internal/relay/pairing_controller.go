package relay

import (
	"context"
	"errors"

	"github.com/ehzyil/connect-hub/internal/relay/contract"
)

func deviceStore(p Persistence) contract.DeviceStore { s, _ := p.(contract.DeviceStore); return s }
func supportsPairing(s ServerInstance) bool {
	if c, ok := s.(interface{ PairingSupported() bool }); ok {
		return c.PairingSupported()
	}
	return false
}
func (s *Server) PairingSupported() bool { return s.pairing.available }

func (c *Controller) PairControl(ctx context.Context, cmd contract.PairCommand) (contract.PairView, error) {
	if err := c.opMu.LockContext(ctx); err != nil {
		return contract.PairView{}, err
	}
	defer c.opMu.Unlock()
	c.mu.Lock()
	server := c.server
	sid := c.settings.ShareID
	c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return contract.PairView{}, err
	}
	if p, ok := server.(contract.PairControl); ok {
		return p.PairControl(ctx, cmd)
	}
	// Paused hosts retain a manageable device list without starting a listener.
	store := deviceStore(c.persist)
	if store == nil || sid == "" {
		return contract.PairView{}, errors.New("配对组件不可用，请先开启共享")
	}
	if cmd.Operation == "list" || cmd.Operation == "revoke" || cmd.Operation == "revoke-all" {
		p, err := newPairingState(ctx, store, sid, "", func(string) {})
		if err != nil {
			return contract.PairView{}, err
		}
		return p.control(ctx, cmd)
	}
	return contract.PairView{}, errors.New("共享暂停或尚未运行")
}

// PauseSharing is explicitly separate from legacy Disable, which destroys the
// share identity and invalidates all v1 codes. Pause survives application restart.
func (c *Controller) PauseSharing(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	finish := c.beginStop()
	defer finish()
	if err := c.opMu.LockContext(ctx); err != nil {
		return err
	}
	defer c.opMu.Unlock()
	c.mu.Lock()
	if err := ctx.Err(); err != nil {
		c.mu.Unlock()
		return err
	}
	if !c.settings.Enabled {
		c.mu.Unlock()
		return errors.New("共享未开启")
	}
	c.settings.Paused = true
	c.opID++
	err := c.persistLocked()
	if err != nil {
		c.restoreSuppressed = true
		c.failure = "暂停状态保存失败，重启可能恢复"
		c.failCode = "persist"
	}
	server, source := c.detachInstanceLocked()
	c.publishLocked()
	c.mu.Unlock()
	return errors.Join(err, closeInstance(ctx, server, source))
}

func (c *Controller) ResumeSharing(ctx context.Context) error {
	if err := c.opMu.LockContext(ctx); err != nil {
		return err
	}
	c.mu.Lock()
	if err := ctx.Err(); err != nil {
		c.mu.Unlock()
		c.opMu.Unlock()
		return err
	}
	c.settings.Paused = false
	err := c.persistLocked()
	if err != nil {
		c.settings.Paused = true
	} else {
		c.restoreSuppressed = false
	}
	c.mu.Unlock()
	c.opMu.Unlock()
	if err != nil {
		return err
	}
	return c.Restore(ctx)
}
