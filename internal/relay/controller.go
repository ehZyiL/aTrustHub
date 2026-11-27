package relay

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ehzyil/connect-hub/internal/lanname"
	contract "github.com/ehzyil/connect-hub/internal/relay/contract"
)

// Controller owns A's share lifecycle: enable intent, restore, suspend, disable
// and shutdown. It never logs in a VPN, never edits the system proxy and never
// changes the selected point behind the user's back.
type Controller struct {
	// Operations may drop mu while closing network resources. Serialize them so
	// a new enable cannot inherit an identity that a concurrent disable revokes.
	opMu         sync.Mutex
	workMu       sync.Mutex // cancellation must not wait for an in-flight AcquireSource
	workCancel   context.CancelFunc
	stopRequests int
	mu           sync.Mutex
	persist      Persistence
	sink         Sink
	nets         NetworkProvider
	logf         func(string, ...any)
	notify       func()

	settings Settings
	state    State
	opID     uint64
	instance string
	failure  string
	failCode string
	cleanup  bool
	started  time.Time
	certEnd  time.Time
	iface    string
	address  string
	port     int

	source        Source
	server        ServerInstance
	serverFactory ServerFactory
	token         string
	identity      *Identity

	// restoreSuppressed locks automatic restore for the rest of this run, used
	// when the disable state could not be persisted.
	restoreSuppressed bool
	closed            bool

	runCancel context.CancelFunc
	runDone   chan struct{}
	kickCh    chan struct{}
	subs      map[chan struct{}]struct{}
}

// NewController builds a controller. It does not start anything: call Restore
// once the configuration and credentials are loaded.
func NewController(p Persistence, sink Sink, nets NetworkProvider, logf func(string, ...any), notify func()) *Controller {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	c := &Controller{
		persist:       p,
		sink:          sink,
		nets:          nets,
		logf:          logf,
		notify:        notify,
		state:         StateOff,
		serverFactory: func(opts ServerOptions) (ServerInstance, error) { return StartServer(opts) },
	}
	c.settings = p.ShareSettings()
	if !c.settings.Enabled {
		c.state = StateOff
	}
	return c
}

// SetServerFactory installs the optional process boundary before Restore or
// Enable. A live server is never migrated in place.
func (c *Controller) SetServerFactory(factory ServerFactory) error {
	if factory == nil {
		return errors.New("分享服务工厂缺失")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.server != nil || c.runDone != nil || c.closed {
		return errors.New("分享服务已启动，不能更换组件")
	}
	c.serverFactory = factory
	return nil
}

// View returns the current immutable view.
func (c *Controller) View() View {
	c.mu.Lock()
	defer c.mu.Unlock()
	view := View{
		Enabled:        c.settings.Enabled,
		State:          c.state,
		Operation:      c.opID,
		PointID:        c.settings.PointID,
		Interface:      c.iface,
		Address:        c.address,
		Port:           c.port,
		StartedAt:      c.started,
		CertExpiry:     c.certEnd,
		Failure:        c.failure,
		FailureCode:    c.failCode,
		CleanupPending: c.cleanup,
		DiscoveryName:  c.settings.DiscoveryName,
	}
	if c.settings.DiscoveryEnabled != nil {
		view.DiscoveryEnabled = *c.settings.DiscoveryEnabled
	}
	if c.sink != nil && c.settings.PointID != "" {
		view.PointName = c.sink.PointName(c.settings.PointID)
	}
	if c.server != nil {
		view.Clients = c.server.ActiveClients()
	}
	return view
}

// Settings returns the persisted settings, for the adapter and for tests.
func (c *Controller) Settings() Settings {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.settings.Clone()
}

// DiscoverySnapshot returns what may be announced right now. ok is false unless
// the share is completely committed and running: the announcement carries the
// address and port that actually bound, never a requested one.
func (c *Controller) DiscoverySnapshot() (DiscoveryAnnouncement, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.settings.Enabled || c.settings.DiscoveryEnabled == nil || !*c.settings.DiscoveryEnabled {
		return DiscoveryAnnouncement{}, false
	}
	if c.state != StateRunning || c.server == nil {
		return DiscoveryAnnouncement{}, false
	}
	if c.settings.ShareID == "" || c.address == "" || c.port == 0 {
		return DiscoveryAnnouncement{}, false
	}
	// The alias may be empty here: the app fills the default from the share ID
	// before publishing, so this package stays independent of model.
	return DiscoveryAnnouncement{
		Generation:      c.opID,
		ShareID:         c.settings.ShareID,
		Name:            c.settings.DiscoveryName,
		ProtocolVersion: ProtocolVersion,
		InterfaceName:   c.iface,
		Address:         c.address,
		Port:            c.port,
	}, true
}

// SetDiscovery changes only the discovery preference. It never restarts the
// share, never touches the token, the certificate, the port or the access point
// selection, and it cannot switch sharing on: a disabled share keeps its
// preference for the next manual enable.
func (c *Controller) SetDiscovery(enabled bool, name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errors.New("分享已退出")
	}
	name = strings.TrimSpace(name)
	if name != "" {
		if err := lanname.Valid(name); err != nil {
			return err
		}
	}
	previous := c.settings.Clone()
	want := enabled
	c.settings.DiscoveryEnabled = &want
	c.settings.DiscoveryName = name
	if err := c.persistLocked(); err != nil {
		c.settings = previous
		return errors.New("发现偏好无法保存：" + err.Error())
	}
	c.publishLocked()
	return nil
}

// ShareCode returns the current share code. It only exists while Running: a
// Waiting or Blocked share must not print something that cannot be used.
func (c *Controller) ShareCode() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != StateRunning || c.server == nil {
		return "", errors.New("共享尚未运行")
	}
	name := ""
	if c.sink != nil {
		name = c.sink.PointName(c.settings.PointID)
	}
	return ShareCode{
		Version:     ShareVersion,
		Host:        c.address,
		Port:        c.port,
		ShareID:     c.settings.ShareID,
		Token:       c.token,
		Fingerprint: c.settings.Fingerprint,
		Name:        name,
	}.String(), nil
}

// publishLocked tells the UI thread that the view changed. It never calls back
// into the controller, so a render pass cannot deadlock the state machine.
func (c *Controller) publishLocked() {
	if c.notify != nil {
		go c.notify()
	}
}

// Enable persists the user's intent and starts serving when possible. It is the
// only path that may switch a share on.
func (c *Controller) Enable(ctx context.Context, opts EnableOptions) error {
	c.opMu.Lock()
	defer c.opMu.Unlock()
	ctx, finish := c.beginWork(ctx)
	defer finish()
	var retired <-chan struct{}
	defer func() {
		if retired != nil {
			<-retired
		}
	}()
	c.mu.Lock()
	defer c.mu.Unlock()
	defer func() {
		if !c.settings.Enabled {
			retired = c.stopLoopLocked()
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.closed {
		return errors.New("分享已退出")
	}
	if opts.PointID == "" {
		return errors.New("请选择要共享的接入点")
	}
	if name := strings.TrimSpace(opts.DiscoveryName); name != "" {
		if err := lanname.Valid(name); err != nil {
			return err
		}
	}
	if c.sink != nil && !c.sink.PointExists(opts.PointID) {
		return errors.New("所选接入点不存在")
	}
	if c.settings.Enabled && c.state != StateOff && c.settings.PointID != "" && c.settings.PointID != opts.PointID {
		return errors.New("请先关闭当前共享，再切换共享接入点")
	}
	if c.state == StateRunning || c.state == StateStarting {
		return nil
	}
	c.opID++
	c.settings.Enabled = true
	c.settings.PointID = opts.PointID
	c.settings.InterfaceName = opts.InterfaceName
	if opts.PreferredIPv4 != "" {
		c.settings.PreferredIPv4 = opts.PreferredIPv4
	}
	if opts.Port >= 0 && opts.Port <= 65535 {
		c.settings.Port = opts.Port
	}
	// The checkbox is an explicit choice, saved with the rest of the intent.
	// Discovery still cannot publish until the share is Running.
	discovery := opts.Discovery
	c.settings.DiscoveryEnabled = &discovery
	c.settings.DiscoveryName = strings.TrimSpace(opts.DiscoveryName)
	c.restoreSuppressed = false
	c.failure, c.failCode = "", ""
	c.state = StateStarting
	c.publishLocked()

	if err := c.ensureIdentityLocked(); err != nil {
		c.rollbackFirstEnableLocked()
		c.failure, c.failCode = err.Error(), "identity"
		c.state = StateOff
		c.publishLocked()
		return err
	}
	if err := c.persistLocked(); err != nil {
		c.rollbackFirstEnableLocked()
		c.failure, c.failCode = "启用状态无法保存："+err.Error(), "persist"
		c.state = StateOff
		c.publishLocked()
		return errors.New(c.failure)
	}
	err := c.reconcileLocked(ctx, true)
	c.startLoopLocked()
	return err
}

// Restore starts the share if the persisted intent says it was on. A VPN that is
// not connected yet leaves it Waiting; nothing logs in automatically.
func (c *Controller) Restore(ctx context.Context) error {
	c.opMu.Lock()
	defer c.opMu.Unlock()
	ctx, finish := c.beginWork(ctx)
	defer finish()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errors.New("分享已退出")
	}
	if !c.settings.Enabled {
		c.state = StateOff
		c.publishLocked()
		return nil
	}
	err := c.reconcileLocked(ctx, false)
	c.startLoopLocked()
	return err
}

// Disable switches sharing off for good: it stops serving, revokes the token and
// persists Enabled=false. A failed persist still stops the network immediately
// and is reported honestly instead of claiming a permanent close.
func (c *Controller) Disable(ctx context.Context) error {
	finishStop := c.beginStop()
	defer finishStop()
	c.opMu.Lock()
	defer c.opMu.Unlock()
	c.mu.Lock()
	c.opID++
	c.restoreSuppressed = true
	c.settings.Enabled = false
	c.state = StateStopping
	c.publishLocked()
	server, source := c.detachInstanceLocked()
	done := c.stopLoopLocked()
	c.mu.Unlock()

	cleanupErr := closeInstance(ctx, server, source)
	if done != nil {
		<-done
	}

	c.mu.Lock()
	shareID := c.settings.ShareID
	// A disabled share keeps no identity: the next enable must mint a new one.
	c.settings.ShareID = ""
	c.settings.Fingerprint = ""
	c.settings.BoundPort = 0
	saveErr := c.persistLocked()
	if saveErr != nil {
		c.settings.ShareID = shareID
		c.failure = "关闭状态未保存，重启可能恢复：" + saveErr.Error()
		c.failCode = "persist"
	} else {
		c.failure, c.failCode = "", ""
		// Only after the disabled state is on disk may the recovery identity
		// and token go away.
		c.dropSecretsLocked(shareID)
	}
	c.state = StateOff
	c.cleanup = cleanupErr != nil
	if cleanupErr != nil {
		c.state = StateCleanupPending
		c.failure = "分享已停止，但连接清理未完成"
		c.failCode = "cleanup"
	}
	c.publishLocked()
	failure := c.failure
	c.mu.Unlock()
	if saveErr != nil {
		return errors.New(failure)
	}
	return cleanupErr
}

// CancelEnable rolls back a first enable that the user cancelled while it was
// starting: no listener, no intent, no identity left behind.
func (c *Controller) CancelEnable(ctx context.Context) error {
	finishStop := c.beginStop()
	defer finishStop()
	c.opMu.Lock()
	defer c.opMu.Unlock()
	c.mu.Lock()
	if !c.settings.Enabled || c.state == StateRunning || c.state == StateWaiting || c.state == StateBlocked {
		c.mu.Unlock()
		return nil
	}
	c.opID++
	c.restoreSuppressed = true
	c.settings.Enabled = false
	server, source := c.detachInstanceLocked()
	done := c.stopLoopLocked()
	c.mu.Unlock()

	err := closeInstance(ctx, server, source)
	if done != nil {
		<-done
	}

	c.mu.Lock()
	shareID := c.settings.ShareID
	c.settings.ShareID = ""
	c.settings.Fingerprint = ""
	c.settings.BoundPort = 0
	_ = c.persistLocked()
	c.dropSecretsLocked(shareID)
	c.state = StateOff
	c.failure, c.failCode = "", ""
	c.publishLocked()
	c.mu.Unlock()
	return err
}

// Suspend stops the running instance but keeps the enable intent, so the next
// start (or restore) serves the same identity, address and port.
func (c *Controller) Suspend(ctx context.Context) error {
	finishStop := c.beginStop()
	defer finishStop()
	c.opMu.Lock()
	defer c.opMu.Unlock()
	c.mu.Lock()
	c.opID++
	server, source := c.detachInstanceLocked()
	enabled := c.settings.Enabled
	if enabled {
		c.state = StateWaiting
	} else {
		c.state = StateOff
	}
	c.publishLocked()
	c.mu.Unlock()
	return closeInstance(ctx, server, source)
}

// Shutdown stops the running instance and the reconcile loop. It keeps Enabled
// and the identity; only Disable clears them.
func (c *Controller) Shutdown(ctx context.Context) error {
	finishStop := c.beginStop()
	defer finishStop()
	c.opMu.Lock()
	defer c.opMu.Unlock()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.opID++
	c.closed = true
	server, source := c.detachInstanceLocked()
	done := c.stopLoopLocked()
	if c.settings.Enabled {
		c.state = StateWaiting
	} else {
		c.state = StateOff
	}
	c.publishLocked()
	c.mu.Unlock()

	err := closeInstance(ctx, server, source)
	if done != nil {
		<-done
	}
	return err
}

// Wake asks the reconcile loop to re-check now, for example after the VPN came
// online or the network changed.
func (c *Controller) Wake() {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case c.kickCh <- struct{}{}:
	default:
	}
}

// Retry clears a Blocked reason and tries again.
func (c *Controller) Retry(ctx context.Context) error {
	c.mu.Lock()
	c.failure, c.failCode = "", ""
	c.mu.Unlock()
	return c.Restore(ctx)
}

// RetryPersistDisable re-attempts saving Enabled=false after a failed disable.
func (c *Controller) RetryPersistDisable() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.settings.Enabled {
		return errors.New("共享仍处于启用状态")
	}
	if err := c.persistLocked(); err != nil {
		c.failure = "关闭状态未保存，重启可能恢复：" + err.Error()
		c.failCode = "persist"
		c.publishLocked()
		return err
	}
	c.failure, c.failCode = "", ""
	shareID := c.settings.ShareID
	c.settings.ShareID = ""
	c.settings.Fingerprint = ""
	c.settings.BoundPort = 0
	_ = c.persistLocked()
	c.dropSecretsLocked(shareID)
	c.publishLocked()
	return nil
}

func (c *Controller) beginWork(parent context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancel(parent)
	c.workMu.Lock()
	c.workCancel = cancel
	if c.stopRequests > 0 {
		cancel()
	}
	c.workMu.Unlock()
	return ctx, func() {
		cancel()
		c.workMu.Lock()
		c.workCancel = nil
		c.workMu.Unlock()
	}
}

func (c *Controller) beginStop() func() {
	c.workMu.Lock()
	c.stopRequests++
	if c.workCancel != nil {
		c.workCancel()
	}
	c.workMu.Unlock()
	return func() {
		c.workMu.Lock()
		c.stopRequests--
		c.workMu.Unlock()
	}
}

// startLoopLocked allocates the watcher only for an explicitly enabled share.
func (c *Controller) startLoopLocked() {
	if c.closed || !c.settings.Enabled || c.restoreSuppressed || c.runDone != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	done, kick := make(chan struct{}), make(chan struct{}, 1)
	c.runCancel, c.runDone, c.kickCh = cancel, done, kick
	go c.loop(ctx, done, kick)
}

// stopLoopLocked detaches the worker; the operation waits outside mu. opMu
// prevents another enable from starting until that wait has completed.
func (c *Controller) stopLoopLocked() <-chan struct{} {
	done := c.runDone
	if c.runCancel != nil {
		c.runCancel()
	}
	c.runCancel, c.runDone, c.kickCh = nil, nil, nil
	return done
}

func (c *Controller) loop(ctx context.Context, done chan struct{}, kick <-chan struct{}) {
	defer close(done)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-kick:
		}
		// A public operation already reconciles or stops the instance. Never
		// wait behind its stop-and-join while holding the worker alive.
		if c.opMu.TryLock() {
			workCtx, finish := c.beginWork(ctx)
			c.reconcileTick(workCtx)
			finish()
			c.opMu.Unlock()
		}
	}
}

// reconcileTick re-checks a share that should be running. A dead source is torn
// down first so a late connection can never cross into the new generation.
func (c *Controller) reconcileTick(ctx context.Context) {
	c.mu.Lock()
	if ctx.Err() != nil || c.closed || !c.settings.Enabled || c.restoreSuppressed {
		c.mu.Unlock()
		return
	}
	if c.state == StateRunning && c.source != nil {
		select {
		case <-c.source.Done():
			c.logf("[局域网分享] 绑定接入点已断开，停止当前实例并等待恢复")
			server, source := c.detachInstanceLocked()
			c.state = StateWaiting
			c.failure, c.failCode = "", ""
			c.publishLocked()
			c.mu.Unlock()
			_ = closeInstance(context.Background(), server, source)
			return
		case <-c.server.Done():
			c.logf("[局域网分享] 分享组件异常退出，VPN 会话保持不变")
			server, source := c.detachInstanceLocked()
			c.state = StateBlocked
			c.failure, c.failCode = "分享组件异常退出，请检查安装并手动重试", "component-exited"
			c.publishLocked()
			c.mu.Unlock()
			_ = closeInstance(context.Background(), server, source)
			return
		default:
			c.mu.Unlock()
			return
		}
	}
	// Only Waiting is retried automatically: a Blocked share needs an explicit
	// 重试恢复 (or a fix), and CleanupPending must never start listening again
	// before its cleanup finished.
	if c.state != StateWaiting {
		c.mu.Unlock()
		return
	}
	// The transition stays atomic with the attempt: an outside observer never
	// sees Starting for an attempt that is not actually being made.
	c.opID++
	c.state = StateStarting
	err := c.reconcileLocked(ctx, false)
	c.mu.Unlock()
	if err != nil {
		c.logf("[局域网分享] 恢复失败：%v", err)
	}
}

// reconcileLocked brings the runtime instance in line with the persisted intent.
// first is true only for a manual first enable, which rolls back instead of
// entering Blocked.
func (c *Controller) reconcileLocked(ctx context.Context, first bool) error {
	if c.closed || !c.settings.Enabled || c.restoreSuppressed {
		return nil
	}
	if c.state == StateRunning && c.server != nil {
		return nil
	}
	cancelled := func() error {
		if first {
			c.rollbackFirstEnableLocked()
			c.state = StateOff
			c.publishLocked()
		}
		return ctx.Err()
	}
	if ctx.Err() != nil {
		return cancelled()
	}
	s := c.settings
	blocked := func(code, msg string) error {
		c.state = StateBlocked
		c.failCode, c.failure = code, msg
		c.publishLocked()
		return errors.New(msg)
	}
	waiting := func(msg string) error {
		unchanged := c.state == StateWaiting && c.failure == msg && c.failCode == ""
		c.state = StateWaiting
		c.failCode, c.failure = "", msg
		if !unchanged {
			c.publishLocked()
		}
		return nil
	}
	if s.ShareID == "" || s.Fingerprint == "" {
		return blocked("identity", "缺少分享身份，请关闭后重新开启共享")
	}
	if c.sink == nil || !c.sink.PointExists(s.PointID) {
		return blocked("point", "共享接入点已不存在，请关闭共享后重新选择")
	}
	address, iface := c.pickAddressLocked(s)
	if address == "" {
		return waiting("共享已启用，等待局域网地址就绪")
	}
	// The identity is bound to one address: a changed address needs a new
	// share code, which the user has to confirm, never a silent rebind.
	if s.PreferredIPv4 != "" && s.PreferredIPv4 != address {
		return blocked("address", fmt.Sprintf("局域网地址已变化（%s → %s），请关闭共享后重新开启并重新分发口令", s.PreferredIPv4, address))
	}
	if c.identity != nil && c.identity.Address != "" && c.identity.Address != address {
		return blocked("address", fmt.Sprintf("局域网地址已变化（%s → %s），请关闭共享后重新开启并重新分发口令", c.identity.Address, address))
	}
	src, err := c.sink.AcquireSource(ctx, s.PointID)
	if ctx.Err() != nil {
		if src != nil {
			_ = src.Close()
		}
		return cancelled()
	}
	if err != nil {
		if errors.Is(err, ErrPointMissing) {
			return blocked("point", "共享接入点已不存在")
		}
		if errors.Is(err, ErrPointUnsupported) || errors.Is(err, ErrPointTunOwned) {
			return blocked("unsupported", err.Error())
		}
		return waiting("共享已启用，等待接入点连接")
	}
	identity, err := c.loadIdentityLocked()
	if err != nil {
		_ = src.Close()
		return blocked("identity", "分享身份不可用："+err.Error())
	}
	if err := VerifyIdentityRecord(identity, address); err != nil {
		_ = src.Close()
		return blocked("certificate", err.Error())
	}
	token, err := c.loadTokenLocked()
	if err != nil || token == "" {
		_ = src.Close()
		return blocked("token", "分享口令不可用，请关闭共享后重新开启")
	}
	port := s.BoundPort
	if port == 0 {
		port = s.Port
	}
	server, err := c.serverFactory(ServerOptions{
		Identity:         identity,
		Source:           src,
		Token:            token,
		ShareID:          s.ShareID,
		ServerInstanceID: c.serverInstanceLocked(),
		Logf:             c.logf,
		Port:             port,
	})
	if ctx.Err() != nil {
		_ = closeInstance(context.Background(), server, src)
		return cancelled()
	}
	if err != nil {
		_ = src.Close()
		if first {
			c.rollbackFirstEnableLocked()
			c.state = StateOff
			c.failCode, c.failure = "listen", err.Error()
			c.publishLocked()
			return err
		}
		return blocked("listen", err.Error())
	}
	c.source = src
	c.server = server
	c.identity = identity
	c.token = token
	c.address = address
	c.iface = iface
	c.port = server.Port()
	c.started = time.Now()
	c.certEnd = identity.NotAfter
	c.state = StateRunning
	c.failure, c.failCode = "", ""
	c.cleanup = false
	c.settings.PreferredIPv4 = address
	c.settings.InterfaceName = iface
	c.settings.BoundPort = c.port
	c.settings.Fingerprint = identity.Fingerprint
	if err := c.persistLocked(); err != nil && first {
		// The port must be on disk before a code is printed, otherwise a
		// restart would bind a different one.
		server2, source2 := c.detachInstanceLocked()
		c.rollbackFirstEnableLocked()
		c.state = StateOff
		c.failCode, c.failure = "persist", "分享端口无法保存："+err.Error()
		c.publishLocked()
		_ = closeInstance(context.Background(), server2, source2)
		return errors.New(c.failure)
	}
	c.logf("[局域网分享] 已在 %s:%d 开启，共享接入点「%s」", address, c.port, c.sink.PointName(s.PointID))
	c.publishLocked()
	return nil
}

func (c *Controller) pickAddressLocked(s Settings) (address, iface string) {
	if c.nets == nil {
		return "", ""
	}
	candidates := c.nets.LANCandidates()
	if s.PreferredIPv4 != "" {
		for _, cand := range candidates {
			if cand.IPv4 == s.PreferredIPv4 {
				return cand.IPv4, cand.Name
			}
		}
	}
	if s.InterfaceName != "" {
		for _, cand := range candidates {
			if cand.Name == s.InterfaceName {
				return cand.IPv4, cand.Name
			}
		}
	}
	if len(candidates) == 0 {
		return "", ""
	}
	return candidates[0].IPv4, candidates[0].Name
}

func (c *Controller) serverInstanceLocked() string {
	if c.instance == "" {
		id, err := randomToken()
		if err != nil {
			// An instance id is diagnostic only; a deterministic fallback still
			// never authorizes anything.
			id = fmt.Sprintf("instance-%d", time.Now().UnixNano())
		}
		c.instance = id
	}
	return c.instance
}

// ensureIdentityLocked creates the share identity and token on first enable.
// Both must be safely stored before any listener exists.
func (c *Controller) ensureIdentityLocked() error {
	if c.settings.ShareID == "" {
		shareID, err := randomShareID()
		if err != nil {
			return errors.New("无法生成分享 ID")
		}
		c.settings.ShareID = shareID
	}
	if err := c.ensureAddressLocked(); err != nil {
		return err
	}
	if c.settings.Fingerprint == "" {
		identity, err := GenerateIdentity(c.address)
		if err != nil {
			return err
		}
		stored, err := EncodeIdentity(identity)
		if err != nil {
			return err
		}
		if err := c.persist.SetSecret(IdentitySecretKey(c.settings.ShareID), stored); err != nil {
			return fmt.Errorf("分享证书无法安全保存：%w", err)
		}
		c.identity = identity
		c.settings.Fingerprint = identity.Fingerprint
	}
	if c.token == "" {
		token, err := randomShareToken()
		if err != nil {
			return errors.New("无法生成分享口令")
		}
		if err := c.persist.SetSecret(ShareTokenKey(c.settings.ShareID), token); err != nil {
			return fmt.Errorf("分享口令无法安全保存：%w", err)
		}
		c.token = token
	}
	return nil
}

// ensureAddressLocked picks the bind address before the certificate is minted,
// because the leaf pins that address.
func (c *Controller) ensureAddressLocked() error {
	if c.address != "" {
		return nil
	}
	address, iface := c.pickAddressLocked(c.settings)
	if address == "" {
		return errors.New("没有可用的局域网地址")
	}
	c.address = address
	c.iface = iface
	c.settings.PreferredIPv4 = address
	c.settings.InterfaceName = iface
	return nil
}

func (c *Controller) loadIdentityLocked() (*Identity, error) {
	if c.identity != nil {
		return c.identity, nil
	}
	stored, err := c.persist.GetSecret(IdentitySecretKey(c.settings.ShareID))
	if err != nil {
		return nil, err
	}
	identity, err := DecodeIdentity(stored)
	if err != nil {
		return nil, err
	}
	if c.settings.Fingerprint != "" && identity.Fingerprint != c.settings.Fingerprint {
		return nil, errors.New("分享证书与记录的指纹不一致")
	}
	c.identity = identity
	return identity, nil
}

func (c *Controller) loadTokenLocked() (string, error) {
	if c.token != "" {
		return c.token, nil
	}
	token, err := c.persist.GetSecret(ShareTokenKey(c.settings.ShareID))
	if err != nil {
		return "", err
	}
	c.token = token
	return token, nil
}

// persistLocked writes the intent. Running is never persisted.
func (c *Controller) persistLocked() error {
	return c.persist.SaveShareSettings(c.settings)
}

// rollbackFirstEnableLocked clears a failed first enable: intent, identity and
// token all go away, so nothing silent is left behind.
func (c *Controller) rollbackFirstEnableLocked() {
	shareID := c.settings.ShareID
	c.settings.Enabled = false
	c.settings.BoundPort = 0
	c.settings.ShareID = ""
	c.settings.Fingerprint = ""
	c.token = ""
	c.identity = nil
	c.address = ""
	c.iface = ""
	_ = c.persistLocked()
	c.dropSecretsLocked(shareID)
}

// dropSecretsLocked removes a share's long-lived secrets. shareID is passed in
// because the caller may already have cleared the settings field.
func (c *Controller) dropSecretsLocked(shareID string) {
	if shareID != "" {
		_ = c.persist.DeleteSecret(IdentitySecretKey(shareID))
		_ = c.persist.DeleteSecret(ShareTokenKey(shareID))
	}
	c.token = ""
	c.identity = nil
}

// detachInstanceLocked removes the running instance from the view and returns it
// so it can be closed outside the lock.
func (c *Controller) detachInstanceLocked() (ServerInstance, Source) {
	server, source := c.server, c.source
	c.server, c.source = nil, nil
	c.address = ""
	c.port = 0
	c.started = time.Time{}
	c.certEnd = time.Time{}
	c.cleanup = false
	if c.settings.Enabled {
		c.state = StateWaiting
	}
	return server, source
}

// closeInstance revokes and stops one instance within the cleanup budget.
func closeInstance(ctx context.Context, server ServerInstance, source Source) error {
	var errs []error
	if server != nil {
		server.RevokeAll()
		if err := server.Close(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if source != nil {
		if err := source.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

type State = contract.State

const StateOff = contract.StateOff

const StateWaiting = contract.StateWaiting

const StateStarting = contract.StateStarting

const StateRunning = contract.StateRunning

const StateBlocked = contract.StateBlocked

const StateStopping = contract.StateStopping

const StateCleanupPending = contract.StateCleanupPending

type Settings = contract.Settings

type Persistence = contract.Persistence

func ShareTokenKey(shareID string) string { return contract.ShareTokenKey(shareID) }

type Interface = contract.Interface

type NetworkProvider = contract.NetworkProvider

type EnableOptions = contract.EnableOptions

type View = contract.View

type DiscoveryAnnouncement = contract.DiscoveryAnnouncement
