package vpn

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	relay "github.com/ehzyil/connect-hub/internal/relay/contract"
	"github.com/ehzyil/connect-hub/internal/routing"
	"github.com/ehzyil/connect-hub/internal/workeripc"
	"github.com/miekg/dns"
)

// ErrRelaySourceUnavailable says the access point cannot be shared right now:
// offline, no strict capability, owned by the old global TUN, or relay-typed.
var ErrRelaySourceUnavailable = errors.New("所选接入点当前不能用于局域网分享")

// RelayShareSource is the strict sharing boundary. Everything a LAN request can
// reach goes through it, so a sharing host can never turn into a public relay.
type RelayShareSource struct {
	m       *Manager
	pointID string
	ep      *endpoint
	gen     int
	sess    Session

	changes chan struct{}
	done    chan struct{}
	once    sync.Once
	closed  atomic.Bool
}

var _ relay.Source = (*RelayShareSource)(nil)

// AcquireRelayShareSource pins the current endpoint identity and returns the
// strict source for it. It refuses a point that cannot prove strict dialing:
// a bare Session is not enough, a process session must also have negotiated a
// VPN address and prepare capability.
func (m *Manager) AcquireRelayShareSource(pointID string) (*RelayShareSource, error) {
	if pointID == "" {
		return nil, ErrRelaySourceUnavailable
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.acquireRelayShareSourceLocked(pointID)
}

func (m *Manager) acquireRelayShareSourceLocked(pointID string) (*RelayShareSource, error) {
	ep := m.points[pointID]
	if ep == nil {
		return nil, ErrRelaySourceUnavailable
	}
	if m.closed || ep.state != StateOnline || ep.sess == nil {
		return nil, ErrRelaySourceUnavailable
	}
	// A relay node may never share itself: that would relay into a loop.
	if ep.cfg.Protocol == "lan_relay" {
		return nil, errors.New("不能分享局域网中继接入点")
	}
	// The old global TUN owns this tunnel; its routing is not this Manager's.
	if ep.tunServed {
		return nil, errors.New("接入点已移交给系统 TUN，暂不能同时分享")
	}
	if !strictCapable(ep.sess) {
		return nil, errors.New("接入点缺少严格 VPN 拨号能力，请更新配套核心")
	}
	src := &RelayShareSource{
		m:       m,
		pointID: pointID,
		ep:      ep,
		gen:     ep.gen,
		sess:    ep.sess,
		changes: make(chan struct{}, 1),
		done:    make(chan struct{}),
	}
	if m.shareSubs == nil {
		m.shareSubs = map[string][]*RelayShareSource{}
	}
	m.shareSubs[pointID] = append(m.shareSubs[pointID], src)
	return src, nil
}

// strictCapable mirrors the aggregate's strict test: either the session really
// implements StrictSession, or it is a process session that has negotiated a
// private VPN address and prepare capability.
func strictCapable(sess Session) bool {
	if sess == nil {
		return false
	}
	if _, ok := sess.(StrictSession); ok {
		if s, isProcess := sess.(*processSession); isProcess {
			f := s.flows.Load()
			return f != nil && f.vpnAddress != "" && f.prepare
		}
		return true
	}
	if s, ok := sess.(*processSession); ok {
		f := s.flows.Load()
		return f != nil && f.vpnAddress != "" && f.prepare
	}
	return false
}

// Snapshot publishes the effective TCP rules of the whole access point: the
// session's raw snapshot after the user's 停用应用 switches, narrowed to TCP.
func (s *RelayShareSource) Snapshot(ctx context.Context) (relay.SourceSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return relay.SourceSnapshot{}, err
	}
	m := s.m
	m.mu.RLock()
	ep := s.currentLocked()
	if ep == nil {
		m.mu.RUnlock()
		return relay.SourceSnapshot{}, net.ErrClosed
	}
	local := ep.info.Resources
	epoch := ep.shareEpoch
	revision := ep.shareRevision
	caps := shareCapabilities(ep.sess)
	m.mu.RUnlock()

	if local == nil {
		return relay.SourceSnapshot{}, relay.NewError(relay.CodeVPNUnavailable, "接入点没有可发布的资源")
	}
	published := relayResources(local).PublishTCP()
	if revision == "" {
		revision = published.Revision(caps)
	}
	snap := relay.SourceSnapshot{Epoch: epoch, Revision: revision, Resources: published, Capabilities: caps}
	if err := snap.Validate(); err != nil {
		return relay.SourceSnapshot{}, err
	}
	return snap, nil
}

// currentLocked returns the endpoint while it still matches the pinned identity.
func (s *RelayShareSource) currentLocked() *endpoint {
	if s.closed.Load() || s.m.closed {
		return nil
	}
	ep := s.m.points[s.pointID]
	if ep != s.ep || ep.gen != s.gen || ep.sess != s.sess || ep.state != StateOnline || ep.tunServed {
		return nil
	}
	return ep
}

// DialVPN is the only way a LAN target reaches the VPN. It requires the exact
// revision the client authenticated against, a strict VPN decision for this
// bound point and revisits that decision after the dial, so a revocation racing
// with a successful connect still closes the connection.
func (s *RelayShareSource) DialVPN(ctx context.Context, revision, target string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m := s.m
	m.mu.RLock()
	ep := s.currentLocked()
	if ep == nil {
		m.mu.RUnlock()
		return nil, relay.NewError(relay.CodeVPNUnavailable, "分享接入点已断开")
	}
	currentRevision := ep.shareRevision
	m.mu.RUnlock()
	if revision != "" && currentRevision != "" && revision != currentRevision {
		return nil, relay.NewError(relay.CodeStaleResources, "资源版本已变化，请刷新后重试")
	}

	// Decision is made against the current snapshot with a trusted binding:
	// any direct policy, unknown target or foreign owner is a refusal.
	request := routing.Request{
		Network:   "tcp",
		Address:   target,
		GatewayID: s.pointID,
		Entry:     "局域网分享",
	}
	decision := m.PreviewRoute(request)
	switch decision.Action {
	case "vpn":
		// Continue below.
	case "direct":
		// A local direct policy must never become a public exit for a LAN
		// share; it only means this target is refused.
		return nil, relay.NewError(relay.CodeResourceDenied, "分享不提供直连出口")
	default:
		reason := decision.Reason
		if reason == "" {
			reason = "目标不在分享范围内"
		}
		return nil, relay.NewError(relay.CodeResourceDenied, "%s", reason)
	}
	bound := false
	for _, candidate := range decision.Candidates {
		if candidate.ID != s.pointID {
			return nil, relay.NewError(relay.CodeResourceDenied, "目标归属其他接入点，分享不转发")
		}
		if candidate.Generation != s.gen {
			return nil, relay.NewError(relay.CodeStaleResources, "接入点会话已更换，请刷新后重试")
		}
		bound = true
	}
	if !bound {
		return nil, relay.NewError(relay.CodeResourceDenied, "分享接入点未授权该目标")
	}

	dialCtx, cancel := context.WithTimeout(ctx, relay.DialTimeout)
	conn, err := safeStrictDial(dialCtx, s.sess, "tcp", decision.Target)
	if err == nil {
		err = dialCtx.Err()
	}
	cancel()
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, relay.NewError(relay.CodeDialTimeout, "分享主机连接目标超时")
		}
		return nil, relay.NewError(relay.CodeTargetUnreachable, "分享主机无法连接目标 %s（%s）",
			decision.Target, dialFailureReason(err))
	}
	// Re-check after the dial: revocation or a source change must not let a
	// just-established connection slip through.
	m.mu.RLock()
	stillCurrent := s.currentLocked() != nil
	current := m.points[s.pointID]
	stillSameRevision := revision == "" || (current != nil && current.shareRevision == revision)
	m.mu.RUnlock()
	if !stillCurrent || !stillSameRevision {
		_ = conn.Close()
		return nil, relay.NewError(relay.CodeShareClosed, "分享已撤销")
	}
	return conn, nil
}

// dialFailureReason turns the worker's transport error into one short reason the
// colleague can act on. The raw text is a socks error that names the host's own
// loopback entry (127.0.0.1:<port>) and prefixes everything with a generic
// "unknown error"; neither helps the client and both describe the host's
// internals, so only the classified reason travels.
func dialFailureReason(err error) string {
	if err == nil {
		return "目标不可达"
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "connection refused"):
		return "连接被拒绝，目标主机上没有服务监听该端口"
	case strings.Contains(msg, "unreachable"), strings.Contains(msg, "no route to host"):
		return "目标不可达，主机不在线或没有可用路由"
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "deadline exceeded"):
		return "连接超时"
	case strings.Contains(msg, "reset by peer"):
		return "连接被目标重置"
	default:
		return "目标不可达"
	}
}

// ExchangeDNS resolves inside the bound session for the exact revision. A late
// answer after a source change is discarded instead of being served.
func (s *RelayShareSource) ExchangeDNS(ctx context.Context, revision string, query []byte) ([]byte, error) {
	exchanger, ok := s.sess.(DNSExchanger)
	if !ok {
		return nil, relay.NewError(relay.CodeProtocolUnsupported, "分享接入点不支持内网 DNS 查询")
	}
	if len(query) == 0 || len(query) > relay.MaxDNSBody {
		return nil, relay.NewError(relay.CodeInvalidRequest, "DNS 查询大小无效")
	}
	question, err := shareDNSQuestion(query)
	if err != nil {
		return nil, err
	}
	m := s.m
	m.mu.RLock()
	ep := s.currentLocked()
	if ep == nil {
		m.mu.RUnlock()
		return nil, relay.NewError(relay.CodeVPNUnavailable, "分享接入点已断开")
	}
	currentRevision := ep.shareRevision
	resources := ep.info.Resources
	m.mu.RUnlock()
	if revision != "" && currentRevision != "" && revision != currentRevision {
		return nil, relay.NewError(relay.CodeStaleResources, "资源版本已变化，请刷新后重试")
	}
	// The share is not an open resolver: only names this access point actually
	// declares may be resolved through it.
	if !shareOwnsName(resources, question) {
		return nil, relay.NewError(relay.CodeDNSUnauthorized, "该名称不属于此分享范围")
	}
	answer, err := exchanger.ExchangeDNS(ctx, query)
	if err != nil {
		return nil, relay.NewError(relay.CodeTargetUnreachable, "内网 DNS 查询失败：%v", err)
	}
	// The answer is only valid for the generation it was asked under. A query
	// can outlive a revocation, so re-check both the session and the resource
	// revision before handing the answer to the client: otherwise a name that
	// was just withdrawn would still be resolved through the share.
	m.mu.RLock()
	stillCurrent := s.currentLocked() != nil
	var revisionNow string
	if cur := m.points[s.pointID]; cur != nil {
		revisionNow = cur.shareRevision
	}
	m.mu.RUnlock()
	if !stillCurrent {
		return nil, relay.NewError(relay.CodeShareClosed, "分享已撤销")
	}
	if revision != "" && revisionNow != revision {
		return nil, relay.NewError(relay.CodeStaleResources, "资源版本已变化，请刷新后重试")
	}
	return answer, nil
}

// Changes coalesces resource/content changes.
func (s *RelayShareSource) Changes() <-chan struct{} { return s.changes }

// Done closes when the pinned session is gone.
func (s *RelayShareSource) Done() <-chan struct{} { return s.done }

// Close releases the adapter only; the VPN keeps running.
func (s *RelayShareSource) Close() error {
	s.detach()
	s.signalChange()
	return nil
}

func (s *RelayShareSource) detach() {
	s.once.Do(func() {
		s.closed.Store(true)
		close(s.done)
	})
}

// signalChange coalesces one pending edge.
func (s *RelayShareSource) signalChange() {
	select {
	case s.changes <- struct{}{}:
	default:
	}
}

// ---- Manager hooks -------------------------------------------------------

// notifyShareResourcesLocked tells live sources that the published scope
// changed. Callers hold m.mu.
func (m *Manager) notifyShareResourcesLocked(pointID string) {
	for _, src := range m.shareSubs[pointID] {
		src.signalChange()
	}
}

// closeShareSourcesLocked ends every source of a point and forgets it. Callers
// hold m.mu. The next enable/restore acquires a fresh generation.
func (m *Manager) closeShareSourcesLocked(pointID string) {
	for _, src := range m.shareSubs[pointID] {
		src.detach()
		src.signalChange()
	}
	delete(m.shareSubs, pointID)
}

// SeedRelayKnown loads persisted attribution into Known before any node starts.
// Known only stops automatic direct dialing; it never authorizes a dial.
// SeedRelayKnownIncomplete seeds what is known while the node's history is known
// to be missing entries. Attribution still protects the targets in this snapshot,
// but the node stays out of the automatic login set and the gate stays on: a
// current authorization can never prove what was withdrawn earlier.
func (m *Manager) SeedRelayKnownIncomplete(pointID string, resources *workeripc.ResourceSnapshot) {
	if resources == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	ep := m.points[pointID]
	if ep == nil {
		return
	}
	ep.knownResources = rememberResources(ep.knownResources, resources)
	if m.autoConnectBlocked == nil {
		m.autoConnectBlocked = map[string]bool{}
	}
	m.autoConnectBlocked[pointID] = true
	m.recomputeHistoryGateLocked()
}

func (m *Manager) SeedRelayKnown(pointID string, resources *workeripc.ResourceSnapshot) {
	if resources == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	ep := m.points[pointID]
	if ep == nil {
		return
	}
	ep.knownResources = rememberResources(ep.knownResources, resources)
	// Verified attribution repairs this node: it may take part in automatic
	// login again. The global gate only lifts when no node is left untrusted.
	delete(m.autoConnectBlocked, pointID)
	m.recomputeHistoryGateLocked()
}

// recomputeHistoryGateLocked keeps the unknown-target gate on while any relay
// node's attribution is still unverified. Repairing one node must not silently
// unprotect the others.
func (m *Manager) recomputeHistoryGateLocked() {
	m.relayHistoryUnverified = len(m.autoConnectBlocked) > 0
}

// BlockRelayAutoConnect keeps one relay node out of the automatic login set
// without touching the user's stored AutoConnect preference. A manual login is
// still allowed, which is how the node gets repaired.
func (m *Manager) BlockRelayAutoConnect(pointID string, blocked bool) {
	m.mu.Lock()
	if m.autoConnectBlocked == nil {
		m.autoConnectBlocked = map[string]bool{}
	}
	if blocked {
		m.autoConnectBlocked[pointID] = true
	} else {
		delete(m.autoConnectBlocked, pointID)
	}
	m.recomputeHistoryGateLocked()
	m.mu.Unlock()
}

// RelayAutoConnectBlocked reports whether a node is held out of the automatic
// login set.
func (m *Manager) RelayAutoConnectBlocked(pointID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.autoConnectBlocked[pointID]
}

// SetRelayHistoryUnverified turns the "unknown targets must not go direct"
// gate on. It is a local routing constraint from local state; a LAN request
// field can never set it.
func (m *Manager) SetRelayHistoryUnverified(v bool) {
	m.mu.Lock()
	m.relayHistoryUnverified = v
	m.mu.Unlock()
}

// RelayHistoryUnverified reports the current gate.
func (m *Manager) RelayHistoryUnverified() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.relayHistoryUnverified
}

// ShareSourceRevision reports the current published revision, for diagnostics.
func (m *Manager) ShareSourceRevision(pointID string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if ep := m.points[pointID]; ep != nil {
		return ep.shareRevision
	}
	return ""
}

// shareDNSQuestion validates one DNS message before it may reach the bound
// session: query only, one question, IN class, no zone transfer and no TSIG.
func shareDNSQuestion(packet []byte) (string, error) {
	var msg dns.Msg
	if err := msg.Unpack(packet); err != nil {
		return "", relay.NewError(relay.CodeInvalidRequest, "DNS 查询无法解析")
	}
	if msg.Response || msg.Opcode != dns.OpcodeQuery {
		return "", relay.NewError(relay.CodeInvalidRequest, "只接受 DNS 查询")
	}
	if len(msg.Question) != 1 {
		return "", relay.NewError(relay.CodeInvalidRequest, "只接受单个问题的 DNS 查询")
	}
	q := msg.Question[0]
	if q.Qclass != dns.ClassINET {
		return "", relay.NewError(relay.CodeInvalidRequest, "只接受 IN class 的 DNS 查询")
	}
	if q.Qtype == dns.TypeAXFR || q.Qtype == dns.TypeIXFR {
		return "", relay.NewError(relay.CodeInvalidRequest, "不接受传输区查询")
	}
	if msg.IsTsig() != nil {
		return "", relay.NewError(relay.CodeInvalidRequest, "不接受 TSIG 签名查询")
	}
	name, err := routing.NormalizeHost(strings.TrimSuffix(q.Name, "."))
	if err != nil || name == "" {
		return "", relay.NewError(relay.CodeDNSUnauthorized, "DNS 查询名称无效")
	}
	return name, nil
}

// shareOwnsName reports whether the snapshot declares name. Static DNS and the
// internal-domain list grant attribution only; the session still validates the
// resolved answer and the business port.
func shareOwnsName(resources *workeripc.ResourceSnapshot, name string) bool {
	if resources == nil {
		return false
	}
	for _, rule := range resources.DomainRules {
		if routing.DomainSpecificity(rule.Domain, name) > 0 {
			return true
		}
	}
	for _, suffix := range resources.InternalDomains {
		if routing.DomainSpecificity(suffix, name) > 0 {
			return true
		}
	}
	for _, record := range resources.StaticDNS {
		if strings.TrimSuffix(strings.ToLower(record.Name), ".") == name {
			return true
		}
	}
	return false
}
