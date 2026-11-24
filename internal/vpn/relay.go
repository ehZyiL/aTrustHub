package vpn

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
	"github.com/ehzyil/connect-hub/internal/workeripc"
)

// SessionUpdate is one immutable snapshot a session publishes after it is
// online. Sequence is strictly increasing per session generation.
type SessionUpdate struct {
	Sequence uint64
	Info     SessionInfo
}

// SessionUpdater is implemented by sessions that can report resource changes
// without reconnecting. Sessions without it keep their original behaviour.
type SessionUpdater interface {
	Updates() <-chan SessionUpdate
}

// RelayConnectorOptions wires the LAN client into the app: the original-network
// dialer and the callback that must persist attribution before a snapshot may be
// published.
type RelayConnectorOptions struct {
	Dial relay.Dialer
	// SaveSnapshot runs before the first online announcement and before every
	// SessionUpdate. Returning an error refuses the snapshot.
	SaveSnapshot func(pointID string, resources *workeripc.ResourceSnapshot) error
}

// NewRelayConnector builds the importing connector for lan_relay nodes.
func NewRelayConnector(opts RelayConnectorOptions) Connector {
	return func(ctx context.Context, point model.AccessPoint, creds Credentials) (Session, error) {
		return connectRelay(ctx, opts, point, creds)
	}
}

func connectRelay(ctx context.Context, opts RelayConnectorOptions, point model.AccessPoint, creds Credentials) (Session, error) {
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
	if opts.SaveSnapshot != nil {
		if err := opts.SaveSnapshot(point.ID, raw); err != nil {
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
		updates: make(chan SessionUpdate, 4),
		ctx:     sessCtx,
		cancel:  sessCancel,
		info:    relayInfo(point, state, raw),
		save:    opts.SaveSnapshot,
	}
	s.seq.Store(1)
	s.wg.Add(1)
	go s.heartbeat()
	return s, nil
}

// friendlyRelayError maps protocol failures to the words the card shows. It never
// says "VPN 密码错误": a share token is a different credential.
func friendlyRelayError(err error) error {
	var re *relay.Error
	if errors.As(err, &re) {
		switch re.Code {
		case relay.CodeInvalidCredentials:
			return errors.New("分享口令无效或已被撤销，请向分享主机获取新口令")
		case relay.CodeProtocolUnsupported:
			return errors.New("分享主机协议版本不兼容，请升级客户端")
		case relay.CodeShareClosed:
			return errors.New("分享已关闭")
		case relay.CodeSessionExpired:
			return errors.New("分享会话已过期，请重新连接")
		case relay.CodeBusy:
			return errors.New("分享主机繁忙，请稍后重试")
		}
		return errors.New(re.Message)
	}
	return err
}

func relayInfo(point model.AccessPoint, state *relay.SessionState, raw *workeripc.ResourceSnapshot) SessionInfo {
	info := SessionInfo{ClientIP: point.Server, Resources: raw}
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
	save    func(string, *workeripc.ResourceSnapshot) error

	mu    sync.RWMutex
	state relay.SessionState
	raw   *workeripc.ResourceSnapshot
	info  SessionInfo
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

	seq     atomic.Uint64
	updates chan SessionUpdate
}

var (
	_ Session        = (*relaySession)(nil)
	_ StrictSession  = (*relaySession)(nil)
	_ SessionWatcher = (*relaySession)(nil)
	_ SessionUpdater = (*relaySession)(nil)
	_ DNSExchanger   = (*relaySession)(nil)
)

func (s *relaySession) Info() SessionInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneSessionInfo(s.info)
}

// DialVPN is the only data path. There is no original-network fallback: a target
// the share does not authorize fails instead of silently going direct.
func (s *relaySession) DialVPN(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" {
		return nil, ErrStrictVPNUnavailable
	}
	if s.closed.Load() {
		return nil, net.ErrClosed
	}
	if _, port, err := net.SplitHostPort(addr); err != nil || port == "" {
		return nil, errors.New("目标必须包含端口")
	}
	epoch, revision := s.currentVersions()
	conn, err := s.client.Dial(ctx, s.token, epoch, revision, addr)
	if err != nil {
		return nil, friendlyRelayError(err)
	}
	return conn, nil
}

// Dial exists only because Session requires it; it is not a fallback path.
func (s *relaySession) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	return s.DialVPN(ctx, network, addr)
}

// ExchangeDNS asks the sharing host to resolve inside its VPN.
func (s *relaySession) ExchangeDNS(ctx context.Context, packet []byte) ([]byte, error) {
	epoch, revision := s.currentVersions()
	return s.client.ExchangeDNS(ctx, s.token, epoch, revision, packet)
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
func (s *relaySession) Updates() <-chan SessionUpdate { return s.updates }

// Close ends the session, its heartbeat and its client lease.
func (s *relaySession) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	s.cancel()
	// Best effort: a bounded revoke must not hold the UI's shutdown.
	ctx, cancel := context.WithTimeout(context.Background(), relay.ControlTimeout)
	_ = s.client.Revoke(ctx, s.token)
	cancel()
	s.client.Close()
	close(s.updates)
	s.wg.Wait()
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
		if err := s.save(s.pointID, raw); err != nil {
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
	info := cloneSessionInfo(s.info)
	s.mu.Unlock()
	select {
	case s.updates <- SessionUpdate{Sequence: seq, Info: info}:
	case <-s.ctx.Done():
	}
	return nil
}

// fail ends the session with a reason.
func (s *relaySession) fail(err error) {
	s.finish(err)
	if s.closed.Swap(true) {
		return
	}
	s.cancel()
	s.client.Close()
}

// RelayReconnectable reports whether err allows the Manager's bounded reconnect
// policy to try again. Terminal credential and protocol failures do not.
func RelayReconnectable(err error) bool {
	var re *relay.Error
	if errors.As(err, &re) {
		return !re.Code.Terminal()
	}
	return true
}
