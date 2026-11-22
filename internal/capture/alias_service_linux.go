package capture

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ehzyil/connect-hub/internal/dnsmapping"
	"github.com/ehzyil/connect-hub/internal/netpolicy"
	"github.com/ehzyil/connect-hub/internal/resolved"
	"github.com/ehzyil/connect-hub/internal/workeripc"
)

type sharedAliases struct {
	route   *aliasRoute
	journal aliasJournal
	dns     resolved.Config
	owner   string
	dormant bool
}

func (s *Service) aliasDir() string { return filepath.Join(s.dir, "aliases") }

// prepareAliases runs before publishing DNS or starting a target process.
// The lease survives individual scope detach, so a worker never changes pools.
func (s *Service) prepareAliases(ctx context.Context, owner string, req aliasRequest) (*sharedAliases, error) {
	if err := dnsmapping.ValidateReservations(req.Reserved); err != nil {
		return nil, err
	}
	if err := req.DNS.Validate(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// During system capture new generations may reserve a dormant pool.
	// The existing exclusive mode lock still prevents any software attach.
	if s.system == nil {
		modeUnlock, err := s.lockCaptureMode(false)
		if err != nil {
			return nil, err
		}
		defer modeUnlock()
	}
	if len(s.aliases) >= 32 {
		return nil, errors.New("capture: too many shared DNS leases")
	}
	for _, a := range s.aliases {
		if a.owner == owner {
			return nil, errors.New("capture: controller already owns a DNS lease")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	unlock, err := s.lockNetwork(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	state, err := snapshot(ctx, s.run)
	if err != nil {
		return nil, err
	}
	reserved := append([]string(nil), req.Reserved...)
	for _, a := range s.aliases {
		reserved = append(reserved, a.route.Prefix)
	}
	otherReservations, err := s.otherAliasReservations()
	if err != nil {
		return nil, err
	}
	reserved = append(reserved, otherReservations...)
	prefix, err := chooseAliasPrefix(state, req.Networks, reserved, req.RequiredPrefix)
	if err != nil {
		return nil, err
	}
	a := &sharedAliases{route: &aliasRoute{ID: randomID(), UID: s.uid, Prefix: prefix}, dns: req.DNS, owner: owner}
	a.journal = aliasJournal{Version: 1, ID: a.route.ID, UID: s.uid, Prefix: prefix, Entries: map[string]aliasRecord{}}
	if err = saveAliasJournal(s.aliasDir(), a.journal); err != nil {
		return nil, err
	}
	// Remember even an incomplete transaction; releaseOwner and recovery own it.
	s.aliases[a.route.ID] = a
	if s.system != nil {
		a.dormant = true
	} else if err = a.route.install(ctx, s.run); err != nil {
		return nil, err
	}
	return a, nil
}

// Dormant pools have no kernel rules, but are still bound to a live worker.
// Read other per-UID journals under the shared network lock so different
// desktop users cannot allocate the same range while their software is idle.
func (s *Service) otherAliasReservations(excludeOwnSystem ...bool) ([]string, error) {
	parent := filepath.Dir(s.dir)
	entries, err := os.ReadDir(parent)
	if err != nil {
		return nil, err
	}
	result, err := s.systemReservations(excludeOwnSystem...)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "connect-hub-capture-") {
			continue
		}
		uid, err := strconv.Atoi(strings.TrimPrefix(entry.Name(), "connect-hub-capture-"))
		if err != nil || uid < 1 || uid == s.uid {
			continue
		}
		root := filepath.Join(parent, entry.Name())
		if err = verifyDirectory(root, 0755); err != nil {
			return nil, err
		}
		dir := filepath.Join(root, "aliases")
		if _, err = os.Lstat(dir); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return nil, err
		}
		if err = verifyDirectory(dir, 0700); err != nil {
			return nil, err
		}
		files, err := os.ReadDir(dir)
		if err != nil {
			return nil, err
		}
		for _, file := range files {
			if !strings.HasSuffix(file.Name(), ".json") {
				continue
			}
			j, err := readAliasJournal(filepath.Join(dir, file.Name()), uid)
			if err != nil {
				return nil, err
			}
			result = append(result, j.Prefix)
		}
	}
	return result, nil
}

func (s *Service) referencedAliases(ref *AliasRef, config *resolved.Config) (*sharedAliases, error) {
	if ref == nil {
		return nil, nil
	}
	a := s.aliases[ref.ID]
	if a == nil || a.owner == "" || subtle.ConstantTimeCompare([]byte(a.owner), []byte(ref.Token)) != 1 || config == nil || !a.dns.Same(*config) {
		return nil, errors.New("capture: shared DNS lease is unavailable or belongs to another controller")
	}
	return a, nil
}

func (s *Service) aliasGroups(id, except string) []string {
	var groups []string
	for key, v := range s.sessions {
		if key != except && v.aliasID == id {
			groups = append(groups, v.lease.Group)
		}
	}
	sort.Strings(groups)
	return groups
}

func (s *Service) aliasControl(ctx context.Context, owner string, req frame) (frame, error) {
	res := frame{Version: ProtocolVersion, Type: req.Type, ID: req.ID}
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.aliases[req.ID]
	if a == nil || a.owner != owner {
		return res, errors.New("capture: DNS lease belongs to another controller or has ended")
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	unlock, err := s.lockNetwork(ctx)
	if err != nil {
		return res, err
	}
	defer unlock()
	switch req.Type {
	case "alias_ping":
		if !a.dormant {
			a.route.mu.Lock()
			err = a.route.verifyLocked(ctx, s.run)
			a.route.mu.Unlock()
		}
	case "alias_publish":
		if len(s.aliasGroups(req.ID, "")) == 0 {
			return res, errors.New("capture: DNS has no attached applications")
		}
		foreign, err := s.otherAliasReservations()
		if err != nil {
			return res, err
		}
		for _, mapping := range req.Mappings {
			target, err := netip.ParseAddr(mapping.Original)
			if err != nil {
				return res, errors.New("capture: invalid original destination")
			}
			for _, other := range s.aliases {
				if netip.MustParsePrefix(other.route.Prefix).Contains(target) {
					return res, errors.New("capture: original destination conflicts with an alias pool")
				}
			}
			for _, prefix := range foreign {
				if netip.MustParsePrefix(prefix).Contains(target) {
					return res, errors.New("capture: original destination conflicts with another user's pool")
				}
			}
		}
		err = a.route.publishSaved(ctx, s.run, s.aliasDir(), &a.journal, req.Mappings)
	default:
		err = errors.New("capture: unsupported DNS lease request")
	}
	res.Active = err == nil
	return res, err
}

// Called with the service mutex and network transaction lock held. Recovery
// restores original destinations only; never adopt old application selection.
func (s *Service) recoverAliases(ctx context.Context) error {
	entries, err := os.ReadDir(s.aliasDir())
	if err != nil {
		return err
	}
	now, err := bootNow()
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(s.aliasDir(), entry.Name())
		j, err := readAliasJournal(path, s.uid)
		if err != nil {
			return err
		}
		a := &sharedAliases{journal: j, route: &aliasRoute{ID: j.ID, UID: j.UID, Prefix: j.Prefix}}
		if j.retirement() <= now {
			if err = a.route.remove(ctx, s.run); err != nil {
				return err
			}
			if err = os.Remove(path); err != nil {
				return err
			}
			delete(s.aliases, j.ID)
			continue
		}
		a.route, err = restoreAliasJournal(ctx, s.run, j, now)
		if err != nil {
			return err
		}
		s.aliases[j.ID] = a
	}
	return nil
}

func (s *Service) retireAliasesLocked(ctx context.Context) error {
	now, err := bootNow()
	if err != nil {
		return err
	}
	for id, a := range s.aliases {
		if len(s.aliasGroups(id, "")) != 0 || a.journal.retirement() > now || s.system != nil && s.system.usesAlias(a) {
			continue
		}
		if !a.dormant {
			if err = a.route.remove(ctx, s.run); err != nil {
				return err
			}
			a.dormant = true
		}
		// Keep only a reservation while the worker/controller is alive. There
		// are no kernel routes/tables or DNS policy left for an idle lease.
		if a.owner != "" {
			continue
		}
		if err = os.Remove(filepath.Join(s.aliasDir(), id+".json")); err != nil && !os.IsNotExist(err) {
			return err
		}
		delete(s.aliases, id)
	}
	return nil
}

func (s *Service) reapAliases(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	unlock, err := s.lockNetwork(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	return s.retireAliasesLocked(ctx)
}

// DrainAliases is used by ExecStopPost/uninstall, which must leave cached
// destinations usable for their bounded lifetime before removing the tables.
func (s *Service) DrainAliases(ctx context.Context) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if err := s.reapAliases(ctx); err != nil {
			return err
		}
		s.mu.Lock()
		n := len(s.aliases)
		s.mu.Unlock()
		if n == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// PublishAliases is deliberately separate from the per-process launch socket:
// one application's stop cannot close DNS for another application.
type AliasLease struct {
	client     *controlClient
	ID, Prefix string
	done       chan struct{}
	process    *Process
}

func PrepareAliases(ctx context.Context, config resolved.Config, networks []netpolicy.Range, reservations ...[]string) (*AliasLease, error) {
	return prepareAliasLease(ctx, config, networks, SocketPath(os.Getuid()), 0, reservations...)
}

// PrepareAliasesForPool also constrains preparation to an already committed
// worker pool. An unavailable identity fails before installing any rules.
func PrepareAliasesForPool(ctx context.Context, config resolved.Config, networks []netpolicy.Range, required string, reserved []string) (*AliasLease, error) {
	return prepareAliasLeaseForPool(ctx, config, networks, SocketPath(os.Getuid()), 0, required, reserved)
}

func prepareAliasLease(ctx context.Context, config resolved.Config, networks []netpolicy.Range, socket string, helperUID uint32, reservations ...[]string) (*AliasLease, error) {
	var reserved []string
	if len(reservations) > 0 {
		reserved = reservations[0]
	}
	return prepareAliasLeaseForPool(ctx, config, networks, socket, helperUID, "", reserved)
}

func prepareAliasLeaseForPool(ctx context.Context, config resolved.Config, networks []netpolicy.Range, socket string, helperUID uint32, required string, reserved []string) (*AliasLease, error) {
	c, err := dialControl(ctx, socket, helperUID)
	if err != nil {
		return nil, err
	}
	res, err := c.call(ctx, frame{Type: "alias_prepare", Alias: &aliasRequest{DNS: config, Networks: networks, Reserved: reserved, RequiredPrefix: required}})
	if err != nil || !res.Active || !sessionPattern.MatchString(res.ID) {
		c.conn.Close()
		if err == nil {
			err = errors.New("capture: helper did not prepare DNS")
		}
		return nil, err
	}
	p := &Process{id: res.ID, client: c, done: make(chan struct{})}
	a := &AliasLease{client: c, ID: res.ID, Prefix: res.Prefix, done: p.done, process: p}
	go func() {
		ticker := time.NewTicker(8 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-p.done:
				return
			case <-ticker.C:
			}
			res, err := c.call(context.Background(), frame{Type: "alias_ping", ID: a.ID})
			if err != nil || !res.Active {
				p.finish(err)
				return
			}
		}
	}()
	return a, nil
}

func (a *AliasLease) Ref() *AliasRef        { return &AliasRef{ID: a.ID, Token: a.client.token} }
func (a *AliasLease) Done() <-chan struct{} { return a.done }
func (a *AliasLease) Publish(ctx context.Context, aliases []workeripc.DNSAlias) error {
	_, err := a.client.call(ctx, frame{Type: "alias_publish", ID: a.ID, Mappings: aliases})
	return err
}
func (a *AliasLease) Close() error { a.process.finish(nil); return a.process.Err() }
