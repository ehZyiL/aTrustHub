package capture

import (
	"context"
	"crypto/subtle"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

func (s *Service) systemControl(ctx context.Context, owner string, req frame) (frame, error) {
	response := frame{Version: ProtocolVersion, Type: req.Type, ID: req.ID}
	s.mu.Lock()
	defer s.mu.Unlock()
	if req.Type == "system_cleanup" {
		if len(req.ID) != 64 {
			return response, errors.New("capture: invalid previous controller identity")
		}
		if s.system != nil {
			if s.system.owner == req.ID {
				return response, s.stopSystem()
			}
			return response, errors.New("capture: previous system owner still has network cleanup pending")
		}
		ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		unlock, err := s.lockNetwork(ctx)
		if err != nil {
			return response, err
		}
		defer unlock()
		return response, recoverSystemJournal(ctx, s.run, s.systemJournalPath())
	}
	if s.system != nil && s.system.owner != owner {
		return response, errors.New("capture: system TUN belongs to another controller")
	}
	ctx, cancel := context.WithTimeout(ctx, 22*time.Second)
	defer cancel()
	switch req.Type {
	case "system_start", "system_sync":
		if req.System == nil {
			return response, errors.New("capture: system configuration missing")
		}
		if err := req.System.validate(); err != nil {
			return response, err
		}
		start := req.Type == "system_start"
		if start == (s.system != nil) {
			return response, errors.New("capture: unexpected system TUN state")
		}
		unlock, err := s.lockNetwork(ctx)
		if err != nil {
			return response, err
		}
		defer unlock()
		if start {
			if err := s.startSystem(ctx, owner, *req.System); err != nil {
				return response, err
			}
		} else if err := s.syncSystem(ctx, *req.System); err != nil {
			return response, err
		}
		state := s.system.state
		response.State, response.Active = &state, true
	case "system_publish":
		if s.system == nil {
			return response, errors.New("capture: system TUN is not active")
		}
		return response, s.system.publish(req.ID, req.Mappings)
	case "system_ping":
		if s.system == nil {
			return response, errors.New("capture: system TUN is not active")
		}
		check, cancel := context.WithTimeout(ctx, 8*time.Second)
		err := s.system.verify(check)
		cancel()
		response.Active = err == nil
		if err != nil {
			err = errors.Join(err, s.stopSystem())
		}
		return response, err
	case "system_stop":
		return response, s.stopSystem()
	}
	return response, nil
}

// Caller holds the service mutex and the network transaction lock.
func (s *Service) startSystem(ctx context.Context, owner string, config SystemConfig) error {
	if _, err := s.systemAliases(config); err != nil {
		return err
	}
	unlock, err := s.lockCaptureMode(true)
	if err != nil {
		return err
	}
	keep := false
	defer func() {
		if !keep {
			unlock()
		}
	}()
	if err := recoverSystemJournal(ctx, s.run, s.systemJournalPath()); err != nil {
		return err
	}
	var reservations map[string]int64
	if old, err := loadSystemJournal(s.systemJournalPath()); err == nil {
		reservations = old.Pools
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	kernel, err := snapshot(ctx, s.run)
	if err != nil {
		return err
	}
	runtime, err := newSystemRuntime(ctx, s.run, s.systemJournalPath(), owner, config, kernel, reservations)
	if err != nil {
		return err
	}
	keep, runtime.unlock, s.system = true, unlock, runtime
	if err := runtime.installRule(ctx); err != nil {
		return errors.Join(err, s.stopSystemLocked())
	}
	if err := s.syncSystem(ctx, config); err != nil {
		return errors.Join(err, s.stopSystemLocked())
	}
	return nil
}

func (s *Service) syncSystem(ctx context.Context, config SystemConfig) error {
	s.system.aliasDir = s.aliasDir()
	shared, err := s.systemAliases(config)
	if err != nil {
		return err
	}
	reserved, err := s.otherAliasReservations(true)
	if err != nil {
		return err
	}
	for _, alias := range s.aliases {
		borrowed := false
		for _, a := range shared {
			borrowed = borrowed || a == alias
		}
		if !borrowed {
			reserved = append(reserved, alias.route.Prefix)
		}
	}
	return s.system.apply(ctx, config, reserved, shared)
}

// A raw prefix or a recovered journal cannot confer VPN permission. Only a
// live per-UID capability may transfer, after every software scope detached.
// The system DNS listener differs from the software listener by design.
func (s *Service) systemAliases(config SystemConfig) (map[string]*sharedAliases, error) {
	result := map[string]*sharedAliases{}
	seen := map[string]bool{}
	for _, resource := range config.Resources {
		if resource.Alias == nil {
			continue
		}
		ref := resource.Alias
		a := s.aliases[ref.ID]
		if a == nil || a.owner == "" || a.route.UID != s.uid ||
			subtle.ConstantTimeCompare([]byte(a.owner), []byte(ref.Token)) != 1 ||
			!slices.Equal(a.dns.Domains, resource.Domains) || resource.Guard ||
			len(resource.Domains) == 0 || seen[ref.ID] || len(s.aliasGroups(ref.ID, "")) != 0 ||
			resource.RequiredPrefix != "" && resource.RequiredPrefix != a.route.Prefix {
			return nil, errors.New("capture: shared system DNS lease is unavailable, busy or belongs to another controller")
		}
		seen[ref.ID], result[resource.ID] = true, a
	}
	return result, nil
}

func (s *Service) stopSystem() error {
	if s.system == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	unlock, err := s.lockNetwork(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	return s.stopSystemLocked()
}

func (s *Service) stopSystemLocked() error {
	// Cancel VPN forwarding while the synthetic routes still guard the pool.
	// Restore DNAT before removing the TUN so cached addresses never have a
	// window in which they can fall through to another VPN's Fake-IP handler.
	s.system.cancel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.system.restoreSharedAliases(ctx, s.aliases); err != nil {
		return err
	}
	if err := s.system.close(); err != nil {
		return err
	}
	s.system.unlock()
	s.system = nil
	return nil
}

func (s *Service) systemReservations(excludeOwn ...bool) ([]string, error) {
	now, err := bootNow()
	if err != nil {
		return nil, err
	}
	dirs, err := os.ReadDir(filepath.Dir(s.dir))
	if err != nil {
		return nil, err
	}
	var paths []string
	if len(excludeOwn) == 0 || !excludeOwn[0] {
		paths = append(paths, s.systemJournalPath())
	}
	for _, entry := range dirs {
		dir := filepath.Join(filepath.Dir(s.dir), entry.Name())
		if dir == s.dir || !strings.HasPrefix(entry.Name(), "connect-hub-capture-") {
			continue
		}
		if err := verifyDirectory(dir, 0755); err != nil {
			return nil, err
		}
		paths = append(paths, filepath.Join(dir, "system-tun.json"))
	}
	var pools []string
	for _, path := range paths {
		j, err := loadSystemJournal(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for pool, expires := range j.Pools {
			if expires > now {
				pools = append(pools, pool)
			}
		}
	}
	return pools, nil
}
