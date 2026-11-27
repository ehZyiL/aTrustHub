package relay

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ServerOptions configures one running share instance.
type ServerOptions struct {
	Identity         *Identity
	Source           Source
	Token            string
	ShareID          string
	ServerInstanceID string
	Logf             func(string, ...any)
	// Lease overrides the client lease; tests shorten it.
	Lease time.Duration
	// Port is the requested listen port. 0 lets the kernel pick one, which is
	// only allowed on a first enable; a restore reuses the persisted port.
	Port int
}

// ServerInstance is the lifecycle boundary owned by Controller. A process
// implementation can keep network connections outside the Hub while the
// controller retains the authorized Source and persisted intent.
type ServerInstance interface {
	Port() int
	ActiveClients() int
	Done() <-chan struct{}
	RevokeAll()
	Close(context.Context) error
}

// ServerFactory creates one listener for a pinned Source. Production can
// replace the in-process implementation with the optional relay process.
type ServerFactory func(ServerOptions) (ServerInstance, error)

// Server is one running LAN share: a TLS listener, the control API and the
// CONNECT tunnels, all bound to one pinned Source.
type Server struct {
	identity *Identity
	source   Source
	token    string
	shareID  string
	instance string
	logf     func(string, ...any)

	ln     net.Listener
	http   *http.Server
	mux    *http.ServeMux
	addr   string
	port   int
	root   context.Context
	cancel context.CancelFunc

	clients  *clientRegistry
	conns    *connTable
	dnsSlots *slotLimiter
	auth     *rateLimiter
	tokenSHA string

	snapMu sync.Mutex
	// snapErrMu guards the last reported snapshot failure, so a share that
	// cannot be served says so once instead of on every client attempt.
	snapErrMu   sync.Mutex
	lastSnapErr string
	snap        SourceSnapshot
	snapAt      time.Time

	mu       sync.Mutex
	stopped  bool
	wg       sync.WaitGroup
	stopCh   chan struct{}
	done     chan struct{}
	doneOnce sync.Once
}

// ListenAddress is the bound address, valid after Start.
func (s *Server) ListenAddress() string { return s.addr }

// Port is the bound port, valid after Start.
func (s *Server) Port() int { return s.port }

// Start binds and serves. It returns only after the listener is up, so the caller
// can persist the real port before advertising a share code.
func StartServer(opts ServerOptions) (*Server, error) {
	if opts.Source == nil {
		return nil, errors.New("分享源缺失")
	}
	if opts.Identity == nil {
		return nil, errors.New("分享身份缺失")
	}
	if opts.Token == "" || opts.ShareID == "" {
		return nil, errors.New("分享凭据缺失")
	}
	tlsConfig, err := ServerTLSConfig(opts.Identity)
	if err != nil {
		return nil, err
	}
	lease := opts.Lease
	if lease <= 0 {
		lease = ClientLease
	}
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	root, cancel := context.WithCancel(context.Background())
	s := &Server{
		identity: opts.Identity,
		source:   opts.Source,
		token:    opts.Token,
		shareID:  opts.ShareID,
		instance: opts.ServerInstanceID,
		logf:     logf,
		root:     root,
		cancel:   cancel,
		clients:  newClientRegistry(MaxActiveClients, lease),
		conns:    newConnTable(MaxBusinessConnsTotal, MaxBusinessConnsEach),
		dnsSlots: newSlotLimiter(MaxDNSConcurrentTotal, MaxDNSConcurrentEach),
		auth:     newRateLimiter(AuthRatePerIP, AuthBurstPerIP, AuthRateGlobal, AuthBurstGlobal),
		tokenSHA: tokenDigest(opts.Token),
		stopCh:   make(chan struct{}),
		done:     make(chan struct{}),
	}
	// A lease that stops being valid takes its client's tunnels and pending
	// work with it, whichever path noticed the expiry.
	s.clients.onEvict = func(c *client) {
		c.cancel()
		s.conns.stopClient(c.token)
	}
	s.mux = http.NewServeMux()
	s.mux.HandleFunc("/v1/sessions", s.handleSessions)
	s.mux.HandleFunc("/v1/sessions/current", s.handleSessionCurrent)
	s.mux.HandleFunc("/v1/status", s.handleStatus)
	s.mux.HandleFunc("/v1/resources", s.handleResources)
	s.mux.HandleFunc("/v1/dns-query", s.handleDNS)

	addr := opts.Identity.Address
	if addr == "" {
		addr = "0.0.0.0"
	}
	if opts.Port < 0 || opts.Port > 65535 {
		cancel()
		return nil, errors.New("分享端口无效")
	}
	ln, err := net.Listen("tcp4", net.JoinHostPort(addr, strconv.Itoa(opts.Port)))
	if err != nil {
		cancel()
		return nil, fmt.Errorf("分享端口无法监听：%w", err)
	}
	s.ln = &limitedListener{Listener: ln, sem: make(chan struct{}, MaxUnauthenticated+MaxBusinessConnsTotal), tlsHandshake: TLSHandshakeTimeout}
	s.addr = ln.Addr().String()
	if _, port, err := net.SplitHostPort(s.addr); err == nil {
		s.port, _ = strconv.Atoi(port)
	}
	s.http = &http.Server{
		Handler:           http.HandlerFunc(s.route),
		ReadHeaderTimeout: TLSHandshakeTimeout,
		MaxHeaderBytes:    MaxHeaderBytes,
		TLSConfig:         tlsConfig,
		BaseContext:       func(net.Listener) context.Context { return root },
		// Handshake failures are expected (wrong pin, scanners); they belong in
		// the app log at most, never on stderr.
		ErrorLog: log.New(io.Discard, "", 0),
	}
	go func() {
		_ = s.http.Serve(tls.NewListener(s.ln, tlsConfig))
		s.doneOnce.Do(func() { close(s.done) })
	}()
	go s.clients.sweep(s.stopCh)
	s.wg.Add(1)
	go s.watchChanges()
	return s, nil
}

// route dispatches CONNECT separately: its request target is an authority, not
// a path, and it becomes a byte stream once the response is written.
func (s *Server) route(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}
	s.mux.ServeHTTP(w, r)
}

// ---- control endpoints ---------------------------------------------------

func (s *Server) protoOK(w http.ResponseWriter, r *http.Request) bool {
	if got := strings.TrimSpace(r.Header.Get(HeaderProtocol)); got != strconv.Itoa(ProtocolVersion) {
		writeError(w, NewError(CodeProtocolUnsupported, "只支持分享协议 v%d", ProtocolVersion))
		return false
	}
	if got := strings.TrimSpace(r.Header.Get(HeaderShareID)); got != s.shareID {
		writeError(w, NewError(CodeInvalidCredentials, "分享 ID 不匹配"))
		return false
	}
	return true
}

// authenticateShare checks the long-lived share token. It is used only for
// creating a session; every other endpoint takes the short client token.
func (s *Server) authenticateShare(r *http.Request) error {
	token, err := bearerToken(r.Header.Get(HeaderAuthorization))
	if err != nil {
		return err
	}
	if !s.auth.allow(clientIP(r)) {
		return NewError(CodeBusy, "认证失败过于频繁，请稍后再试")
	}
	if !equalBytes([]byte(tokenDigest(token)), []byte(s.tokenSHA)) {
		return NewError(CodeInvalidCredentials, "分享口令无效或已被撤销")
	}
	return nil
}

// authenticateClient checks a client session token and renews its lease.
func (s *Server) authenticateClient(w http.ResponseWriter, r *http.Request) (*client, error) {
	token, err := bearerToken(r.Header.Get(HeaderAuthorization))
	if err != nil {
		return nil, err
	}
	if token == s.token {
		// The long-lived share token is deliberately not accepted outside
		// session creation: it must not travel on every request.
		return nil, NewError(CodeInvalidCredentials, "请先创建客户端会话")
	}
	c := s.clients.lookup(token, time.Now())
	if c == nil {
		return nil, NewError(CodeSessionExpired, "客户端会话已过期，请重新认证")
	}
	// Any authenticated request proves the client is still there, so the lease is
	// renewed here rather than only on /v1/status: a client that polls resources
	// or opens tunnels every second must not be dropped after one lease period
	// for the lack of a heartbeat, and the error it would get ("请重新认证")
	// hides the real cause.
	if _, ok := s.clients.touch(c, time.Now()); !ok {
		return nil, NewError(CodeSessionExpired, "客户端会话已过期，请重新认证")
	}
	return c, nil
}

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeError(w, NewError(CodeInvalidRequest, "只支持 POST"))
		return
	}
	if !s.protoOK(w, r) {
		return
	}
	if err := s.authenticateShare(r); err != nil {
		writeError(w, err)
		return
	}
	body, err := readBounded(r.Body, MaxSessionBody)
	if err != nil {
		writeError(w, err)
		return
	}
	var req SessionRequest
	if err := decodeStrictJSON(body, &req); err != nil {
		writeError(w, err)
		return
	}
	if !validClientID(req.ClientID) {
		writeError(w, NewError(CodeInvalidRequest, "客户端实例 ID 无效"))
		return
	}
	snap, err := s.snapshot(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	if err := snap.Validate(); err != nil {
		writeError(w, err)
		return
	}
	token, err := randomToken()
	if err != nil {
		writeError(w, NewError(CodeBusy, "分享主机无法生成会话凭据"))
		return
	}
	now := time.Now()
	if _, cerr := s.clients.create(req.ClientID, sanitizeClientName(req.Name), token, now); cerr == errReauth {
		// A retry of an existing instance replaces its lease instead of
		// counting as a second client.
		s.clients.replace(req.ClientID, sanitizeClientName(req.Name), token, now)
	} else if cerr != nil {
		writeError(w, cerr)
		return
	}
	resp := SessionResponse{
		Version:          ProtocolVersion,
		ShareID:          s.shareID,
		ServerInstanceID: s.instance,
		ClientID:         req.ClientID,
		ClientToken:      token,
		Epoch:            snap.Epoch,
		Revision:         snap.Revision,
		Capabilities:     snap.Capabilities,
		LeaseSeconds:     int(s.clients.lease.Seconds()),
		Resources:        snap.Resources,
	}
	writeJSON(w, resp)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeError(w, NewError(CodeInvalidRequest, "只支持 GET"))
		return
	}
	if !s.protoOK(w, r) {
		return
	}
	c, err := s.authenticateClient(w, r)
	if err != nil {
		writeError(w, err)
		return
	}
	snap, serr := s.snapshot(r.Context())
	if serr != nil {
		writeError(w, serr)
		return
	}
	remaining, ok := s.clients.touch(c, time.Now())
	if !ok {
		writeError(w, NewError(CodeInvalidCredentials, "客户端会话已过期，请重新认证"))
		return
	}
	resp := StatusResponse{
		Version:          ProtocolVersion,
		ShareID:          s.shareID,
		ServerInstanceID: s.instance,
		Epoch:            snap.Epoch,
		Revision:         snap.Revision,
		LeaseSeconds:     remaining,
		RemainingSeconds: remaining,
		Capabilities:     snap.Capabilities,
		Clients:          s.clients.count(time.Now()),
	}
	writeJSON(w, resp)
}

func (s *Server) handleResources(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeError(w, NewError(CodeInvalidRequest, "只支持 GET"))
		return
	}
	if !s.protoOK(w, r) {
		return
	}
	if _, err := s.authenticateClient(w, r); err != nil {
		writeError(w, err)
		return
	}
	snap, err := s.snapshot(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	etag := `"` + snap.Revision + `"`
	// Compare tolerantly: a client may send the bare revision or the quoted entity
	// tag. Refusing to match on the bare form made every conditional refresh a
	// full snapshot download.
	if strings.Trim(r.Header.Get(HeaderIfNoneMatch), `"`) == snap.Revision {
		w.Header().Set(HeaderETag, etag)
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set(HeaderETag, etag)
	writeJSON(w, ResourcesResponse{Version: ProtocolVersion, Epoch: snap.Epoch, Revision: snap.Revision, Resources: snap.Resources})
}

func (s *Server) handleDNS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeError(w, NewError(CodeInvalidRequest, "只支持 POST"))
		return
	}
	if !s.protoOK(w, r) {
		return
	}
	c, err := s.authenticateClient(w, r)
	if err != nil {
		writeError(w, err)
		return
	}
	// The documented v1 body is a raw DNS message; epoch and revision travel in
	// the protocol headers so the query itself stays a standard wire format.
	if ct := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type"))); ct != "" && ct != DNSMediaType {
		writeError(w, NewError(CodeInvalidRequest, "DNS 查询必须是 %s", DNSMediaType))
		return
	}
	snap, err := s.snapshot(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	if !snap.Capabilities.InternalDNS {
		writeError(w, NewError(CodeProtocolUnsupported, "分享主机不支持内网 DNS 查询"))
		return
	}
	if got := strings.TrimSpace(r.Header.Get(HeaderShareEpoch)); got != "" {
		if n, perr := strconv.ParseUint(got, 10, 64); perr != nil || n != snap.Epoch {
			writeError(w, NewError(CodeStaleResources, "资源版本已变化，请刷新后重试"))
			return
		}
	}
	if rev := strings.TrimSpace(r.Header.Get(HeaderResourceRev)); rev != "" && rev != snap.Revision {
		writeError(w, NewError(CodeStaleResources, "资源版本已变化，请刷新后重试"))
		return
	}
	query, err := readBounded(r.Body, MaxDNSBody)
	if err != nil {
		writeError(w, err)
		return
	}
	if len(query) == 0 {
		writeError(w, NewError(CodeInvalidRequest, "DNS 查询为空"))
		return
	}
	release, err := s.dnsSlots.acquire(c.token)
	if err != nil {
		writeError(w, err)
		return
	}
	defer release()
	ctx, cancel := context.WithTimeout(c.ctx, ControlTimeout)
	defer cancel()
	answer, err := s.source.ExchangeDNS(ctx, snap.Revision, query)
	if err != nil {
		if c.ctx.Err() != nil {
			writeError(w, NewError(CodeInvalidCredentials, "客户端会话已过期，请重新认证"))
			return
		}
		writeError(w, err)
		return
	}
	w.Header().Set("Content-Type", DNSMediaType)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(answer)
}

func (s *Server) handleSessionCurrent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		w.Header().Set("Allow", http.MethodDelete)
		writeError(w, NewError(CodeInvalidRequest, "只支持 DELETE"))
		return
	}
	if !s.protoOK(w, r) {
		return
	}
	c, err := s.authenticateClient(w, r)
	if err != nil {
		writeError(w, err)
		return
	}
	// Removing the lease also cancels its pending dials and closes its tunnels.
	s.clients.remove(c.token)
	w.WriteHeader(http.StatusNoContent)
}

// ---- CONNECT -------------------------------------------------------------

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	// A CONNECT carries no body: bytes after the request line would otherwise be
	// indistinguishable from tunnel data and be forwarded to the upstream.
	if r.ContentLength > 0 || len(r.TransferEncoding) > 0 || r.Header.Get("Content-Length") != "" {
		writeError(w, NewError(CodeInvalidRequest, "CONNECT 不能带请求体"))
		return
	}
	if !s.protoOK(w, r) {
		return
	}
	c, err := s.authenticateClient(w, r)
	if err != nil {
		writeError(w, err)
		return
	}
	snap, err := s.snapshot(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	if got := strings.TrimSpace(r.Header.Get(HeaderShareEpoch)); got != "" {
		if n, err := strconv.ParseUint(got, 10, 64); err != nil || n != snap.Epoch {
			writeError(w, NewError(CodeStaleResources, "分享资源代次已变化，请刷新后重试"))
			return
		}
	}
	revision := strings.TrimSpace(r.Header.Get(HeaderResourceRev))
	if revision != "" && revision != snap.Revision {
		writeError(w, NewError(CodeStaleResources, "分享资源版本已变化，请刷新后重试"))
		return
	}
	target, err := connectTarget(r)
	if err != nil {
		writeError(w, err)
		return
	}
	entry, err := s.conns.acquire(c.token, snap.Epoch)
	if err != nil {
		writeError(w, err)
		return
	}
	defer s.conns.release(entry)

	// The dial is bound to the lease, the share's lifecycle and this entry's
	// resource generation, not to this request: a revocation, an expired lease
	// or a generation switch must abort a dial that has not completed yet,
	// otherwise a late success would become a tunnel the share already withdrew.
	dialCtx, dialCancel := context.WithTimeout(c.ctx, DialTimeout+TLSHandshakeTimeout)
	ctx, cancel := mergeCancel(dialCtx, entry.ctx)
	upstream, err := s.source.DialVPN(ctx, snap.Revision, target)
	cancel()
	dialCancel()
	if err != nil {
		switch {
		case c.ctx.Err() != nil:
			writeError(w, NewError(CodeInvalidCredentials, "客户端会话已过期，请重新认证"))
		case entry.ctx.Err() != nil && !s.isStopped():
			// The generation changed while this dial was running.
			s.writeRetiredError(w)
		case errors.Is(err, context.Canceled) || s.isStopped():
			writeError(w, NewError(CodeShareClosed, "分享已关闭"))
		default:
			writeError(w, err)
		}
		return
	}
	if !entry.attach(upstream) {
		// The generation was retired or the lease was revoked while dialing;
		// attach already closed the upstream connection.
		s.writeRetiredError(w)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		writeError(w, NewError(CodeInvalidRequest, "连接无法升级"))
		return
	}
	down, buf, err := hj.Hijack()
	if err != nil {
		writeError(w, NewError(CodeInvalidRequest, "连接升级失败"))
		return
	}
	down = WrapBuffered(down, buf.Reader)
	if !entry.attach(down) {
		_ = down.Close()
		return
	}
	_ = down.SetDeadline(time.Time{})

	// A successful CONNECT response carries no Content-Length or
	// Transfer-Encoding: everything after the blank line is opaque bytes.
	if _, err := io.WriteString(down, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	relayTunnel(down, upstream)
}

// connectTarget validates the CONNECT authority. It refuses anything that would
// ask the host to guess: a missing port, userinfo, a path, a query, IPv6 or a
// target that is not host:port.
func connectTarget(r *http.Request) (string, error) {
	target := strings.TrimSpace(r.Host)
	if target == "" {
		target = strings.TrimSpace(r.URL.Host)
	}
	if target == "" {
		return "", NewError(CodeInvalidRequest, "缺少连接目标")
	}
	if strings.ContainsAny(target, "/?#@ \t\r\n") {
		return "", NewError(CodeInvalidRequest, "连接目标只能是 host:port")
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return "", NewError(CodeInvalidRequest, "连接目标必须包含端口")
	}
	if host == "" {
		return "", NewError(CodeInvalidRequest, "连接目标缺少主机")
	}
	if strings.Contains(host, ":") || net.ParseIP(host) != nil && net.ParseIP(host).To4() == nil {
		return "", NewError(CodeInvalidRequest, "首版只支持 IPv4 目标")
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", NewError(CodeInvalidRequest, "连接目标端口无效")
	}
	return net.JoinHostPort(host, port), nil
}

// relayTunnel copies in both directions and closes both ends when either side
// finishes. Half-close is preserved where the connection supports it.
func relayTunnel(down, up net.Conn) {
	defer down.Close()
	defer up.Close()
	done := make(chan struct{}, 2)
	go func() {
		_, err := io.Copy(up, down)
		_ = CloseWrite(up)
		if err != nil {
			_ = up.Close()
		}
		done <- struct{}{}
	}()
	go func() {
		_, err := io.Copy(down, up)
		_ = CloseWrite(down)
		if err != nil {
			_ = down.Close()
		}
		done <- struct{}{}
	}()
	<-done
}

// ---- snapshot, shutdown --------------------------------------------------

// snapshot returns the authorized generation, with a short cache so a burst of
// requests cannot turn into a burst of VPN reads. Any read that discovers a new
// generation commits it through commitLocked, so revocation is never skipped
// because a different request already refreshed the cache.
func (s *Server) snapshot(ctx context.Context) (SourceSnapshot, error) {
	s.snapMu.Lock()
	defer s.snapMu.Unlock()
	if !s.snapAt.IsZero() && time.Since(s.snapAt) < 200*time.Millisecond && s.snap.Revision != "" {
		return s.snap, nil
	}
	ctx, cancel := context.WithTimeout(ctx, ControlTimeout)
	defer cancel()
	next, err := s.source.Snapshot(ctx)
	if err != nil {
		return SourceSnapshot{}, err
	}
	if err := next.Validate(); err != nil {
		// The host is the only place this is diagnosable: the client just gets
		// "invalid_request". Log it once per distinct reason so the sharer can
		// see why colleagues cannot join.
		s.logSnapshotFailure(err)
		return SourceSnapshot{}, err
	}
	s.logSnapshotRecovered()
	s.commitLocked(next)
	return s.snap, nil
}

// commitLocked publishes a snapshot as the authorized generation. The comparison
// is always against the last committed snapshot, never against a fresh read:
// re-reading the source after a change notification returns the new version and
// would make the change look like a no-op.
//
// A generation switch retires the previous generation's tunnels before the new
// snapshot becomes visible, so an in-flight dial either finishes under the old
// generation and is closed, or is refused as stale.
func (s *Server) commitLocked(next SourceSnapshot) {
	cur := s.snap
	if cur.Revision != "" {
		if next.Epoch == cur.Epoch && next.Revision == cur.Revision {
			s.snapAt = time.Now()
			return
		}
		if next.Epoch < cur.Epoch {
			// A stale answer must not roll the share back.
			s.snapAt = time.Now()
			return
		}
		s.logf("分享资源已更新（代次 %d），断开旧业务连接", next.Epoch)
		s.conns.retireBefore(next.Epoch)
	}
	s.snap = next
	s.snapAt = time.Now()
}

func (s *Server) invalidateSnapshot() {
	s.snapMu.Lock()
	s.snapAt = time.Time{}
	s.snapMu.Unlock()
}

// watchChanges reacts to a resource change: the epoch moves and, conservatively,
// every business connection of this share is closed. Control leases stay valid,
// so clients refresh their snapshot instead of re-authenticating.
func (s *Server) watchChanges() {
	defer s.wg.Done()
	for {
		select {
		case <-s.stopCh:
			return
		case <-s.source.Done():
			// The source is gone: no generation is authorized any more, so no
			// business connection may keep running on the old one.
			s.invalidateSnapshot()
			s.conns.closeAll()
			return
		case <-s.source.Changes():
			s.invalidateSnapshot()
			if _, err := s.snapshot(s.root); err != nil {
				// The new authorization cannot be read, so the old one may
				// already be void. Stop carrying business traffic and keep the
				// control leases so clients can refresh when it recovers.
				s.logf("分享资源刷新失败，暂停新授权：%v", err)
				s.conns.closeAll()
			}
		}
	}
}

func (s *Server) isStopped() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopped
}

// mergeCancel returns a context cancelled when either parent is done.
func mergeCancel(a, b context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(a)
	stop := context.AfterFunc(b, cancel)
	return ctx, func() {
		stop()
		cancel()
	}
}

// writeRetiredError distinguishes a permanent stop from a superseded generation.
func (s *Server) writeRetiredError(w http.ResponseWriter) {
	if s.isStopped() {
		writeError(w, NewError(CodeShareClosed, "分享已关闭"))
		return
	}
	writeError(w, NewError(CodeStaleResources, "分享资源已更新，请刷新后重试"))
}

// ActiveClients is the number of live client leases, not TCP connections.
func (s *Server) ActiveClients() int { return s.clients.count(time.Now()) }

// Done closes when the listener stops, including an unexpected Serve failure.
func (s *Server) Done() <-chan struct{} { return s.done }

// RevokeAll drops every client session and every accepted connection, and cancels
// anything still in flight (pending dials and DNS queries) by ending the share's
// lifecycle context. The listener is closed by Close.
func (s *Server) RevokeAll() {
	s.clients.removeAll()
	s.conns.stopAll()
	s.cancel()
}

// Close stops serving, revokes every credential it issued and closes all accepted
// connections, including Hijacked ones.
func (s *Server) Close(ctx context.Context) error {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return nil
	}
	s.stopped = true
	s.mu.Unlock()

	close(s.stopCh)
	s.cancel()
	s.clients.removeAll()
	s.conns.stopAll()
	if s.ln != nil {
		_ = s.ln.Close()
	}
	if s.http != nil {
		shutdown, cancel := context.WithTimeout(ctx, CleanupBudget)
		defer cancel()
		if err := s.http.Shutdown(shutdown); err != nil {
			_ = s.http.Close()
		}
	}
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-time.After(CleanupBudget):
		return errors.New("分享连接清理未在期限内完成")
	}
}

// ---- helpers -------------------------------------------------------------

func writeJSON(w http.ResponseWriter, value any) {
	data, err := marshalBounded(value)
	if err != nil {
		writeError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func marshalBounded(value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, NewError(CodeInvalidRequest, "响应编码失败")
	}
	if len(data) > MaxSnapshotBytes+MaxErrorBody {
		return nil, NewError(CodeInvalidRequest, "响应超过大小上限")
	}
	return data, nil
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// limitedListener bounds concurrently accepted connections. It caps handshake
// and failed-auth floods without sleeping inside a handler; the TLS handshake
// timeout closes a stalled peer.
type limitedListener struct {
	net.Listener
	sem          chan struct{}
	tlsHandshake time.Duration
}

func (l *limitedListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.sem <- struct{}{}
	return &limitedConn{Conn: conn, release: func() { <-l.sem }}, nil
}

type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

// slotLimiter bounds concurrent DNS queries globally and per client.
type slotLimiter struct {
	total     chan struct{}
	maxPerOne int
	mu        sync.Mutex
	per       map[string]int
}

func newSlotLimiter(total, each int) *slotLimiter {
	return &slotLimiter{total: make(chan struct{}, total), maxPerOne: each, per: map[string]int{}}
}

func (l *slotLimiter) acquire(token string) (func(), error) {
	select {
	case l.total <- struct{}{}:
	default:
		return nil, NewError(CodeBusy, "DNS 查询并发已满")
	}
	l.mu.Lock()
	if l.per[token] >= l.maxPerOne {
		l.mu.Unlock()
		<-l.total
		return nil, NewError(CodeBusy, "该客户端的 DNS 查询并发已满")
	}
	l.per[token]++
	l.mu.Unlock()
	return func() {
		l.mu.Lock()
		l.per[token]--
		if l.per[token] <= 0 {
			delete(l.per, token)
		}
		l.mu.Unlock()
		<-l.total
	}, nil
}

// randomToken returns a client session token. A randomness failure aborts the
// authentication instead of falling back to a predictable value.
func randomToken() (string, error) {
	b := make([]byte, shareTokenLen)
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// logSnapshotFailure reports why a snapshot cannot be published to colleagues.
// The client only ever sees "invalid_request", so without this line the host has
// no way to learn that nobody can join.
func (s *Server) logSnapshotFailure(err error) {
	s.snapErrMu.Lock()
	repeated := s.lastSnapErr == err.Error()
	s.lastSnapErr = err.Error()
	s.snapErrMu.Unlock()
	if repeated {
		return
	}
	s.logf("分享资源无法发布：%v", err)
}

// logSnapshotRecovered closes the loop once a previously failing snapshot is
// publishable again.
func (s *Server) logSnapshotRecovered() {
	s.snapErrMu.Lock()
	had := s.lastSnapErr != ""
	s.lastSnapErr = ""
	s.snapErrMu.Unlock()
	if had {
		s.logf("分享资源已恢复，可以接受同事加入")
	}
}
