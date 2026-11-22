package capture

import (
	"bufio"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ehzyil/connect-hub/internal/netpolicy"
	"github.com/ehzyil/connect-hub/internal/proxy"
	"github.com/ehzyil/connect-hub/internal/resolved"
	xproxy "golang.org/x/net/proxy"
	"golang.org/x/sys/unix"
	"net/netip"
)

const leaseTimeout = 35 * time.Second

type capturedSession struct {
	lease   ruleLease
	ingress *TCP
	owner   string
	aliasID string
	unlock  func()
}

// Service is a per-UID system service. Its only privileged work is installing
// owned network rules and accepting transparent TCP; it cannot execute client
// commands. Target software is launched by the unprivileged GUI.
type Service struct {
	uid        int
	dir        string
	networkDir string
	run        commandFunc
	mu         sync.Mutex
	sessions   map[string]*capturedSession
	aliases    map[string]*sharedAliases
	system     *systemRuntime
	lock       *os.File
	failure    chan error
}

func NewService(uid int) (*Service, error) {
	if os.Geteuid() != 0 || uid < 1 {
		return nil, errors.New("capture: service requires root and a non-root authorized UID")
	}
	return newService(uid, RuntimeDir(uid), systemCommand)
}

func newService(uid int, dir string, run commandFunc) (*Service, error) {
	if uid < 1 {
		return nil, errors.New("capture: invalid authorized UID")
	}
	if err := secureDirectory(dir, 0755); err != nil {
		return nil, err
	}
	if err := secureDirectory(filepath.Join(dir, "journal"), 0700); err != nil {
		return nil, err
	}
	if err := secureDirectory(filepath.Join(dir, "aliases"), 0700); err != nil {
		return nil, err
	}
	networkDir := filepath.Join(filepath.Dir(dir), "connect-hub-capture")
	if err := secureDirectory(networkDir, 0755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("capture: unsafe service lock")
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("capture: another helper is running")
	}
	s := &Service{uid: uid, dir: dir, networkDir: networkDir, run: run, sessions: map[string]*capturedSession{}, aliases: map[string]*sharedAliases{}, lock: f, failure: make(chan error, 1)}
	if err := s.Recover(context.Background()); err != nil {
		f.Close()
		return nil, err
	}
	return s, nil
}

// Recover is called before listening and by systemd's ExecStopPost. Kernel
// resources are not adopted after a crash: old owners and SOCKS leases are gone.
func (s *Service) Recover(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sessions) > 0 || s.system != nil {
		return errors.New("capture: cannot recover while sessions are active")
	}
	for _, a := range s.aliases {
		if a.owner != "" {
			return errors.New("capture: cannot recover a live DNS controller")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	unlock, err := s.lockNetwork(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	entries, err := os.ReadDir(filepath.Join(s.dir, "journal"))
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(s.dir, "journal", e.Name())
		l, err := readJournal(path, s.uid)
		if err != nil {
			return err
		}
		if err := removeRules(ctx, s.run, l); err != nil {
			return err
		}
		if l.DNS != nil {
			if err := resolved.Remove(ctx, resolved.Command(s.run), *l.DNS); err != nil {
				return err
			}
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	return errors.Join(recoverSystemJournal(ctx, s.run, s.systemJournalPath()), s.recoverAliases(ctx))
}

func (s *Service) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var errs []error
	errs = append(errs, s.stopSystem())
	for id := range s.sessions {
		if err := s.stop(id); err != nil {
			errs = append(errs, err)
		}
	}
	for _, a := range s.aliases {
		a.owner = ""
	}
	if s.lock != nil {
		errs = append(errs, s.lock.Close())
		s.lock = nil
	}
	return errors.Join(errs...)
}

func (s *Service) attach(ctx context.Context, owner string, req attachRequest) error {
	if err := req.Upstream.validate(); err != nil {
		return err
	}
	p, err := validateProcess(s.uid, req)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	modeUnlock, err := s.lockCaptureMode(false)
	if err != nil {
		return err
	}
	keepMode := false
	defer func() {
		if !keepMode {
			modeUnlock()
		}
	}()
	if len(s.sessions) >= maxSessions {
		return errors.New("capture: too many active launch sessions")
	}
	if s.sessions[req.ID] != nil {
		return errors.New("capture: launch scope is already attached")
	}
	alias, err := s.referencedAliases(req.Upstream.Alias, req.Upstream.DNS)
	if err != nil {
		return err
	}
	// A failed cleanup remains journalled and blocks reuse of that identity.
	if _, err := os.Lstat(filepath.Join(s.dir, "journal", req.ID+".json")); !os.IsNotExist(err) {
		return errors.New("capture: launch scope has pending recovery")
	}
	dialer, err := proxy.NewSOCKSDialer(req.Upstream.Address, &xproxy.Auth{User: req.Upstream.Username, Password: req.Upstream.Password})
	if err != nil {
		return err
	}
	ingress, err := ListenTCP(context.Background(), "127.0.0.1:0", func(ctx context.Context, network, target string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(target)
		ip := net.ParseIP(host)
		if err != nil || ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
			return nil, errors.New("capture: target is not a redirected unicast connection")
		}
		return dialer.DialContext(ctx, network, target)
	})
	if err != nil {
		return err
	}
	success := false
	defer func() {
		if !success {
			ingress.Close()
		}
	}()
	_, portText, _ := net.SplitHostPort(ingress.Addr().String())
	port, _ := strconv.Atoi(portText)
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	unlock, err := s.lockNetwork(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	state, err := snapshot(ctx, s.run)
	if err != nil {
		return err
	}
	if alias != nil && alias.dormant {
		// Other network software may have claimed the range while no kernel
		// table was present. Restrict allocation to our original pool and fail
		// rather than change a live worker's identity or override that route.
		var excluded []string
		for i := 0; i < 32; i++ {
			if p := aliasCandidate(i).String(); p != alias.route.Prefix {
				excluded = append(excluded, p)
			}
		}
		if _, err = chooseAliasPrefix(state, req.Upstream.Networks, excluded); err != nil {
			return err
		}
		now, err := bootNow()
		if err != nil {
			return err
		}
		alias.route, err = restoreAliasJournal(ctx, s.run, alias.journal, now)
		if err != nil {
			return err
		}
		alias.dormant = false
	}
	known := make([]ruleLease, 0, len(s.sessions))
	for _, running := range s.sessions {
		known = append(known, running.lease)
	}
	l, err := allocate(state, s.uid, req.ID, p.Group, port, known...)
	if err != nil {
		return err
	}
	l.Networks = req.Upstream.Networks
	if alias != nil {
		p := netip.MustParsePrefix(alias.route.Prefix)
		b := p.Addr().As4()
		l.Networks = append(append([]netpolicy.Range(nil), l.Networks...), netpolicy.Range{Min: p.Addr().String(), Max: netip.AddrFrom4([4]byte{b[0], b[1], b[2] + 15, 255}).String()})
		l.Networks, err = netpolicy.Compact(l.Networks)
		if err != nil {
			return err
		}
	}
	newDNS := false
	if req.Upstream.DNS != nil {
		for _, existing := range s.sessions {
			if existing.lease.DNS != nil && existing.lease.DNS.Config.Same(*req.Upstream.DNS) {
				l.DNS = existing.lease.DNS
				break
			}
		}
		if l.DNS == nil {
			l.DNS, err = resolved.Prepare(ctx, resolved.Command(s.run), *req.Upstream.DNS)
			if err != nil {
				return err
			}
			newDNS = true
		} else if err := resolved.Verify(ctx, resolved.Command(s.run), *l.DNS); err != nil {
			return err
		}
	}
	if err := saveJournal(filepath.Join(s.dir, "journal"), l); err != nil {
		return err
	}
	s.sessions[req.ID] = &capturedSession{lease: l, ingress: ingress, owner: owner, unlock: modeUnlock}
	keepMode = true
	if alias != nil {
		s.sessions[req.ID].aliasID = alias.route.ID
		if err := alias.route.setGroups(ctx, s.run, s.aliasGroups(alias.route.ID, "")); err != nil {
			return errors.Join(err, s.stopLocked(req.ID))
		}
	}
	if newDNS {
		if err := resolved.Install(ctx, resolved.Command(s.run), *l.DNS); err != nil {
			return errors.Join(err, s.stopLocked(req.ID))
		}
	}
	if err := installRules(ctx, s.run, l); err != nil {
		return errors.Join(err, s.stopLocked(req.ID))
	}
	if err := verifyRules(ctx, s.run, l); err != nil {
		return errors.Join(err, s.stopLocked(req.ID))
	}
	installed, err := snapshot(ctx, s.run)
	if err != nil {
		return errors.Join(err, s.stopLocked(req.ID))
	}
	l.NFTDigest, err = tableDigest(installed, l)
	if err != nil {
		return errors.Join(err, s.stopLocked(req.ID))
	}
	if err := saveJournal(filepath.Join(s.dir, "journal"), l); err != nil {
		return errors.Join(err, s.stopLocked(req.ID))
	}
	s.sessions[req.ID].lease = l
	// The barrier must still be the same process when the acknowledgement is
	// sent. PID reuse or an early exit rolls back before releasing the program.
	if _, err := validateProcess(s.uid, req); err != nil {
		return errors.Join(err, s.stopLocked(req.ID))
	}
	success = true
	return nil
}

// stop is called under mu. Removal precedes listener closure. A failed removal
// keeps its journal for service restart; no other application's state is reset.
func (s *Service) stop(id string) error {
	if s.sessions[id] == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	unlock, err := s.lockNetwork(ctx)
	if err != nil {
		_ = s.sessions[id].ingress.Close()
		if unlock := s.sessions[id].unlock; unlock != nil {
			unlock()
		}
		delete(s.sessions, id)
		select {
		case s.failure <- err:
		default:
		}
		return err
	}
	defer unlock()
	return s.stopWithContextLocked(ctx, id)
}

func (s *Service) stopLocked(id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return s.stopWithContextLocked(ctx, id)
}

func (s *Service) stopWithContextLocked(ctx context.Context, id string) error {
	v := s.sessions[id]
	if v == nil {
		return nil
	}
	var err error
	if v.lease.DNS != nil {
		shared := false
		for other, active := range s.sessions {
			if other != id && active.lease.DNS != nil && active.lease.DNS.ID == v.lease.DNS.ID {
				shared = true
				break
			}
		}
		if !shared {
			err = errors.Join(err, resolved.Remove(ctx, resolved.Command(s.run), *v.lease.DNS))
		}
	}
	// Revoke selected-domain routing before dropping the transparent listener.
	// All remaining scopes keep their DNS mapping and per-port authority.
	if a := s.aliases[v.aliasID]; a != nil {
		groups := s.aliasGroups(v.aliasID, id)
		if e := removeRulesUpdatingAliases(ctx, s.run, v.lease, a.route, groups); e != nil {
			// Configuration loss ends every lease through failure. Restore only
			// original destinations immediately, preserving cached DNS results.
			now, clockErr := bootNow()
			if clockErr == nil {
				var restored *aliasRoute
				restored, clockErr = restoreAliasJournal(ctx, s.run, a.journal, now)
				if clockErr == nil {
					a.route = restored
				}
			}
			err = errors.Join(err, e, clockErr)
			err = errors.Join(err, removeRules(ctx, s.run, v.lease))
		}
	} else {
		err = errors.Join(err, removeRules(ctx, s.run, v.lease))
	}
	_ = v.ingress.Close()
	if v.unlock != nil {
		v.unlock()
	}
	delete(s.sessions, id)
	if err != nil {
		select {
		case s.failure <- err:
		default:
		}
		return err
	}
	err = os.Remove(filepath.Join(s.dir, "journal", id+".json"))
	if err != nil {
		select {
		case s.failure <- err:
		default:
		}
	}
	return err
}

func (s *Service) releaseOwner(owner string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.system != nil {
		s.system.revokeAliasOwner(owner)
	}
	if s.system != nil && s.system.owner == owner {
		if err := s.stopSystem(); err != nil {
			select {
			case s.failure <- err:
			default:
			}
		}
	}
	for id, v := range s.sessions {
		a := s.aliases[v.aliasID]
		if v.owner == owner || (a != nil && a.owner == owner) {
			_ = s.stop(id)
		}
	}
	for _, a := range s.aliases {
		if a.owner == owner {
			a.owner = ""
		}
	}
}

func (s *Service) handle(ctx context.Context, c *net.UnixConn) {
	defer c.Close()
	cred, err := peerCredentials(c)
	if err != nil || int(cred.Uid) != s.uid {
		return
	}
	owner := randomID() + randomID()
	defer s.releaseOwner(owner)
	_ = c.SetDeadline(time.Now().Add(leaseTimeout))
	if err := writeFrame(c, frame{Version: ProtocolVersion, Type: "hello", Token: owner}); err != nil {
		return
	}
	r := bufio.NewReaderSize(c, maxFrame)
	for {
		_ = c.SetReadDeadline(time.Now().Add(leaseTimeout))
		var req frame
		if err := readFrame(r, &req); err != nil {
			return
		}
		if req.Version != ProtocolVersion || subtle.ConstantTimeCompare([]byte(req.Token), []byte(owner)) != 1 {
			return
		}
		res := frame{Version: ProtocolVersion, Type: req.Type, ID: req.ID}
		var err error
		switch req.Type {
		case "system_start", "system_sync", "system_publish", "system_ping", "system_stop", "system_cleanup":
			res, err = s.systemControl(ctx, owner, req)
		case "alias_prepare":
			if req.Alias == nil {
				err = errors.New("capture: missing DNS lease request")
			} else {
				var a *sharedAliases
				a, err = s.prepareAliases(ctx, owner, *req.Alias)
				if err == nil {
					res.ID, res.Prefix, res.Active = a.route.ID, a.route.Prefix, true
				}
			}
		case "alias_ping", "alias_publish":
			res, err = s.aliasControl(ctx, owner, req)
		case "attach":
			if req.Attach == nil {
				err = errors.New("capture: missing attachment")
			} else {
				err = s.attach(ctx, owner, *req.Attach)
				res.ID = req.Attach.ID
				res.Active = err == nil
			}
		case "ping", "detach":
			s.mu.Lock()
			v := s.sessions[req.ID]
			if v != nil && v.owner != owner {
				err = errors.New("capture: session belongs to another controller")
			} else if v != nil {
				if req.Type == "detach" {
					err = s.stop(req.ID)
				} else {
					// One budget covers every verification command. A slow D-Bus
					// daemon must not exhaust the client's entire lease before
					// rollback can run and report the original failure.
					checkCtx, cancelCheck := context.WithTimeout(ctx, 8*time.Second)
					var populated bool
					populated, err = groupPopulated(v.lease.Group)
					if err == nil && populated {
						err = verifyRules(checkCtx, s.run, v.lease)
					}
					if err == nil && populated && v.lease.DNS != nil {
						err = resolved.Verify(checkCtx, resolved.Command(s.run), *v.lease.DNS)
					}
					if err == nil && populated && v.aliasID != "" {
						a := s.aliases[v.aliasID]
						if a == nil || a.owner == "" {
							err = errors.New("capture: DNS controller ended")
						} else {
							a.route.mu.Lock()
							err = a.route.verifyLocked(checkCtx, s.run)
							a.route.mu.Unlock()
						}
					}
					cancelCheck()
					if err != nil || !populated {
						err = errors.Join(err, s.stop(req.ID))
					} else {
						res.Active = true
					}
				}
			}
			s.mu.Unlock()
		default:
			err = errors.New("capture: unsupported control request")
		}
		if err != nil {
			res.Error = err.Error()
		}
		_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := writeFrame(c, res); err != nil {
			return
		}
	}
}

func (s *Service) Serve(ctx context.Context) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	path := filepath.Join(s.dir, "control.sock")
	if st, err := os.Lstat(path); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return errors.New("capture: control path is not a socket")
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return err
	}
	defer ln.Close()
	if err := os.Chmod(path, 0600); err != nil {
		return err
	}
	if err := os.Chown(path, s.uid, -1); err != nil {
		return err
	}
	var mu sync.Mutex
	connections := map[*net.UnixConn]bool{}
	var wg sync.WaitGroup
	defer wg.Wait()
	finished := make(chan struct{})
	defer close(finished)
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-finished:
				return
			case <-ticker.C:
			}
			if err := s.reapAliases(ctx); err != nil && ctx.Err() == nil {
				cancel(err)
				return
			}
		}
	}()
	go func() {
		select {
		case <-ctx.Done():
		case <-finished:
		case err := <-s.failure:
			cancel(err)
		}
		ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for c := range connections {
			c.Close()
		}
	}()
	for {
		c, err := ln.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				if errors.Is(context.Cause(ctx), context.Canceled) {
					return nil
				}
				return context.Cause(ctx)
			}
			return fmt.Errorf("capture: control listener failed: %w", err)
		}
		mu.Lock()
		if len(connections) >= maxSessions*2+2 {
			mu.Unlock()
			c.Close()
			continue
		}
		connections[c] = true
		mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { mu.Lock(); delete(connections, c); mu.Unlock() }()
			s.handle(ctx, c)
		}()
	}
}
