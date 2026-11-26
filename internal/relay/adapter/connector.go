package adapter

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/ehzyil/connect-hub/internal/relay"
	relaycontract "github.com/ehzyil/connect-hub/internal/relay/contract"
	session "github.com/ehzyil/connect-hub/internal/vpn/contract"
	"github.com/ehzyil/connect-hub/internal/workeripc"
)

// Options wires the LAN client into the app: the original-network
// dialer and the callback that must persist attribution before a snapshot may be
// published.
type Options struct {
	Dial relay.Dialer
	// SaveSnapshot runs before the first online announcement and before every
	// session.SessionUpdate. Returning an error refuses the snapshot.
	SaveSnapshot func(pointID string, source relaycontract.RelaySnapshotSource, resources *workeripc.ResourceSnapshot) error
}

// NewConnector builds the importing connector for lan_relay nodes.
func NewConnector(opts Options) session.Connector {
	return func(ctx context.Context, point model.AccessPoint, creds session.Credentials) (session.Session, error) {
		return connectRelay(ctx, opts, point, creds)
	}
}

func connectRelay(ctx context.Context, opts Options, point model.AccessPoint, creds session.Credentials) (session.Session, error) {
	if point.Relay == nil {
		return nil, errors.New("分享节点缺少身份信息，请重新导入分享口令")
	}
	if point.Relay.Version != 1 {
		return nil, fmt.Errorf("分享协议版本 %d 不受支持", point.Relay.Version)
	}
	if creds.Login == "" {
		return nil, errors.New("分享口令缺失，请重新导入")
	}
	code := relay.ShareCode{
		Version:     point.Relay.Version,
		Host:        point.Server,
		Port:        point.Port,
		ShareID:     point.Relay.ShareID,
		Token:       creds.Login,
		Fingerprint: point.Relay.CertificateSHA256,
		Name:        point.Name,
	}
	client, err := relay.NewClient(relay.ClientOptions{Code: code, Dial: opts.Dial})
	if err != nil {
		return nil, err
	}
	// The construction context only bounds the first authentication. The session
	// gets its own context so the Manager cancelling this one cannot kill the
	// heartbeat.
	budget, cancel := context.WithTimeout(ctx, relay.FirstConnectBudget)
	state, token, err := client.Open(budget)
	cancel()
	if err != nil {
		client.Close()
		return nil, friendlyRelayError(err)
	}
	raw := workerResources(state.Resources)
	source := relaycontract.RelaySnapshotSource{ShareID: point.Relay.ShareID, Fingerprint: point.Relay.CertificateSHA256}
	if opts.SaveSnapshot != nil {
		if err := opts.SaveSnapshot(point.ID, source, raw); err != nil {
			client.Close()
			return nil, fmt.Errorf("历史归属无法保存：%w", err)
		}
	}
	sessCtx, sessCancel := context.WithCancel(context.Background())
	s := &relaySession{
		pointID: point.ID,
		host:    point.Server,
		client:  client,
		token:   token,
		state:   *state,
		raw:     raw,
		done:    make(chan struct{}),
		updates: make(chan session.SessionUpdate, 4),
		ctx:     sessCtx,
		cancel:  sessCancel,
		info:    relayInfo(point, state, raw),
		save:    opts.SaveSnapshot,
		source:  source,
	}
	s.seq.Store(1)
	s.wg.Add(1)
	go s.heartbeat()
	return s, nil
}

// displayError replaces the wording of an error without hiding it. The wrapped
// error keeps its code and retry classification: the presentation text must
// never turn a terminal failure into something the reconnect policy retries.
type displayError struct {
	msg   string
	cause error
}

func (e *displayError) Error() string { return e.msg }

func (e *displayError) Unwrap() error { return e.cause }

func display(err error, msg string) error {
	if err == nil {
		return nil
	}
	return &displayError{msg: msg, cause: err}
}

// friendlyRelayError maps protocol failures to the words the card shows. It never
// says "VPN 密码错误": a share token is a different credential.
func friendlyRelayError(err error) error {
	var re *relay.Error
	if errors.As(err, &re) {
		switch re.Code {
		case relay.CodeInvalidCredentials:
			return display(err, "分享口令无效或已被撤销，请向分享主机获取新口令")
		case relay.CodeProtocolUnsupported:
			return display(err, "分享主机协议版本不兼容，请升级客户端")
		case relay.CodeShareClosed:
			return display(err, "分享已关闭")
		case relay.CodeSessionExpired:
			return display(err, "分享会话已过期，请重新连接")
		case relay.CodeBusy:
			return display(err, "分享主机繁忙，请稍后重试")
		}
		return display(err, re.Message)
	}
	return err
}

func relayInfo(point model.AccessPoint, state *relay.SessionState, raw *workeripc.ResourceSnapshot) session.SessionInfo {
	info := session.SessionInfo{ClientIP: point.Server, Resources: raw}
	if raw != nil {
		info.DNSServer = raw.DNSServer
	}
	return info
}

// relaySession is a pure-Go session over the LAN share. It declares only what it
// can enforce: strict TCP. It never pretends to be a transparent capture source.
type relaySession struct {
	pointID string
	host    string
	client  *relay.Client
	token   string
	save    func(string, relaycontract.RelaySnapshotSource, *workeripc.ResourceSnapshot) error
	// source is the identity this session authenticated with.
	source relaycontract.RelaySnapshotSource

	mu    sync.RWMutex
	state relay.SessionState
	raw   *workeripc.ResourceSnapshot
	info  session.SessionInfo
	err   error
	// unreachableSince marks when the host first failed to answer, so a
	// transient blip cannot turn into an endless retry.
	unreachableSince time.Time

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	done   chan struct{}
	once   sync.Once
	closed atomic.Bool
	failed atomic.Bool

	// refreshMu serialises generation refreshes triggered by stale requests and
	// the heartbeat.
	refreshMu   sync.Mutex
	seq         atomic.Uint64
	updates     chan session.SessionUpdate
	updatesOnce sync.Once
}

var (
	_ session.Session        = (*relaySession)(nil)
	_ session.StrictSession  = (*relaySession)(nil)
	_ session.SessionWatcher = (*relaySession)(nil)
	_ session.SessionUpdater = (*relaySession)(nil)
	_ session.DNSExchanger   = (*relaySession)(nil)
)

func (s *relaySession) Info() session.SessionInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return session.CloneInfo(s.info)
}

// DialVPN is the only data path. There is no original-network fallback: a target
// the share does not authorize fails instead of silently going direct.
func (s *relaySession) DialVPN(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" {
		return nil, session.ErrStrictVPNUnavailable
	}
	if s.closed.Load() {
		return nil, net.ErrClosed
	}
	if _, port, err := net.SplitHostPort(addr); err != nil || port == "" {
		return nil, errors.New("目标必须包含端口")
	}
	epoch, revision := s.currentVersions()
	conn, err := s.client.Dial(ctx, s.token, epoch, revision, addr)
	if err != nil && staleShare(err) {
		// The share published a new generation since the last heartbeat. The
		// business request is still valid, so refresh once and retry instead of
		// failing a user action that a 5s heartbeat would have fixed anyway.
		if refreshErr := s.refreshAfterStale(ctx); refreshErr == nil {
			epoch, revision = s.currentVersions()
			conn, err = s.client.Dial(ctx, s.token, epoch, revision, addr)
		}
	}
	if err != nil {
		return nil, friendlyRelayError(err)
	}
	return conn, nil
}

// staleShare reports whether the share refused a request only because the client
// still used the previous resource generation.
func staleShare(err error) bool {
	var re *relay.Error
	return errors.As(err, &re) && re.Code == relay.CodeStaleResources
}

// refreshAfterStale pulls the current generation once. The mutex keeps a burst of
// concurrent business requests from each refreshing and publishing separately.
func (s *relaySession) refreshAfterStale(ctx context.Context) error {
	if s.closed.Load() {
		return net.ErrClosed
	}
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	if s.closed.Load() {
		return net.ErrClosed
	}
	cctx, cancel := context.WithTimeout(ctx, relay.ControlTimeout)
	defer cancel()
	status, err := s.client.Status(cctx, s.token)
	if err != nil {
		return err
	}
	return s.refresh(status)
}

// Dial exists only because session.Session requires it; it is not a fallback path.
func (s *relaySession) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	return s.DialVPN(ctx, network, addr)
}

// ExchangeDNS asks the sharing host to resolve inside its VPN.
func (s *relaySession) ExchangeDNS(ctx context.Context, packet []byte) ([]byte, error) {
	epoch, revision := s.currentVersions()
	answer, err := s.client.ExchangeDNS(ctx, s.token, epoch, revision, packet)
	if err != nil && staleShare(err) {
		if refreshErr := s.refreshAfterStale(ctx); refreshErr == nil {
			epoch, revision = s.currentVersions()
			answer, err = s.client.ExchangeDNS(ctx, s.token, epoch, revision, packet)
		}
	}
	return answer, err
}

func (s *relaySession) currentVersions() (uint64, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.Epoch, s.state.Revision
}

func (s *relaySession) Done() <-chan struct{} { return s.done }

func (s *relaySession) Err() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.err
}

// Updates streams resource snapshots after the first one.
func (s *relaySession) Updates() <-chan session.SessionUpdate { return s.updates }

// Close ends the session, its heartbeat and its client lease. It is idempotent
// and still completes cleanup after fail: terminating and reaping are separate
// steps, so the Manager's later Close never returns early on a dead session.
func (s *relaySession) Close() error {
	first := !s.closed.Swap(true)
	if first && !s.failed.Load() {
		// Best effort: a bounded revoke must not hold the UI's shutdown. A
		// session that already ended (revoked token, closed share) has nothing
		// to revoke.
		ctx, cancel := context.WithTimeout(context.Background(), relay.ControlTimeout)
		_ = s.client.Revoke(ctx, s.token)
		cancel()
	}
	s.cancel()
	s.client.Close()
	// Stop the heartbeat before closing the update stream: a send racing with
	// close() would panic. Closing after the wait means there is no sender left.
	s.wg.Wait()
	s.closeUpdates()
	s.finish(nil)
	return nil
}

// finish records the terminal reason once and closes Done.
func (s *relaySession) finish(err error) {
	s.once.Do(func() {
		s.mu.Lock()
		if err != nil {
			s.err = err
		} else if s.err == nil {
			s.err = errors.New("分享会话已结束")
		}
		s.mu.Unlock()
		close(s.done)
	})
}

// heartbeat keeps the lease alive and refreshes resources on a version change.
func (s *relaySession) heartbeat() {
	defer s.wg.Done()
	ticker := time.NewTicker(relay.HeartbeatInterval)
	defer ticker.Stop()
	s.mu.RLock()
	leaseUntil := time.Now().Add(s.state.Lease)
	s.mu.RUnlock()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
		}
		if time.Now().After(leaseUntil) {
			s.fail(errors.New("分享租约已过期"))
			return
		}
		ctx, cancel := context.WithTimeout(s.ctx, relay.ControlTimeout)
		status, err := s.client.Status(ctx, s.token)
		cancel()
		if err != nil {
			if s.ctx.Err() != nil {
				return
			}
			var re *relay.Error
			if errors.As(err, &re) && re.Code.Terminal() {
				s.fail(friendlyRelayError(err))
				return
			}
			// A transient network failure gets a bounded budget instead of an
			// endless retry: after it we report and stop, and the Manager's
			// reconnect policy decides what happens next.
			if s.deadlineExceeded() {
				s.fail(errors.New("分享主机持续不可达，请检查网络或对方是否已关闭共享"))
				return
			}
			continue
		}
		leaseUntil = time.Now().Add(time.Duration(status.RemainingSeconds) * time.Second)
		if status.RemainingSeconds <= 0 {
			leaseUntil = time.Now().Add(time.Duration(status.LeaseSeconds) * time.Second)
		}
		// A successful heartbeat clears the unreachable budget, so one old
		// blip cannot shorten a later failure window.
		s.mu.Lock()
		s.unreachableSince = time.Time{}
		s.mu.Unlock()
		if err := s.refresh(status); err != nil {
			var re *relay.Error
			if errors.As(err, &re) && re.Code.Terminal() {
				s.fail(friendlyRelayError(err))
				return
			}
			// A bad snapshot is refused rather than published: the old
			// attribution stays and the node is shown as unavailable.
			s.fail(fmt.Errorf("分享资源无法更新：%w", err))
			return
		}
	}
}

// leaving tracks when the share first became unreachable, for the bounded retry
// budget.
func (s *relaySession) deadlineExceeded() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.unreachableSince.IsZero() {
		s.unreachableSince = time.Now()
	}
	return time.Since(s.unreachableSince) > 30*time.Second
}

// refresh applies a newer epoch/revision.
func (s *relaySession) refresh(status *relay.StatusResponse) error {
	s.mu.RLock()
	same := status.Epoch == s.state.Epoch && status.Revision == s.state.Revision
	s.mu.RUnlock()
	if same {
		return nil
	}
	ctx, cancel := context.WithTimeout(s.ctx, relay.ControlTimeout)
	defer cancel()
	resp, notModified, err := s.client.Resources(ctx, s.token, "")
	if err != nil {
		return err
	}
	if notModified {
		return errors.New("分享主机报告了新版本却没有返回快照")
	}
	if resp.Epoch < status.Epoch {
		return errors.New("分享主机返回了过期快照")
	}
	if err := resp.Resources.Validate(); err != nil {
		return err
	}
	raw := workerResources(resp.Resources)
	if s.save != nil {
		if err := s.save(s.pointID, s.source, raw); err != nil {
			return fmt.Errorf("历史归属无法保存：%w", err)
		}
	}
	seq := s.seq.Add(1)
	s.mu.Lock()
	s.state.Epoch = resp.Epoch
	s.state.Revision = resp.Revision
	s.state.Resources = resp.Resources
	s.raw = raw
	s.info.Resources = raw
	if raw != nil {
		s.info.DNSServer = raw.DNSServer
	}
	info := session.CloneInfo(s.info)
	s.mu.Unlock()
	select {
	case s.updates <- session.SessionUpdate{Sequence: seq, Info: info}:
	case <-s.ctx.Done():
	}
	return nil
}

// fail ends the session with a reason. The terminal reason is published once and
// immediately; the cleanup that has to wait for the heartbeat cannot run on the
// heartbeat's own goroutine, so it is handed to a short-lived reaper.
func (s *relaySession) fail(err error) {
	s.failed.Store(true)
	s.finish(err)
	if !s.closed.Swap(true) {
		s.cancel()
		s.client.Close()
	}
	go func() {
		// The sender closes the update stream only after its last send.
		s.wg.Wait()
		s.closeUpdates()
	}()
}

// closeUpdates closes the update stream exactly once, whoever gets there first.
func (s *relaySession) closeUpdates() {
	s.updatesOnce.Do(func() { close(s.updates) })
}
