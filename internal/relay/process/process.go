// Package process runs the LAN share listener in the optional relay process.
// The Hub retains the VPN Source; only authenticated, revision-bound calls are
// brokered to that source over a private loopback data channel.
package process

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/ehzyil/connect-hub/internal/relay"
	contract "github.com/ehzyil/connect-hub/internal/relay/contract"
	"github.com/ehzyil/connect-hub/internal/relay/ctxlock"
	discovery "github.com/ehzyil/connect-hub/internal/relay/discovery/contract"
	vpncontract "github.com/ehzyil/connect-hub/internal/vpn/contract"
)

const ProtocolVersion = "relay-process-v1"

const maxBrokerMessage = contract.MaxSnapshotBytes + (64 << 10)

type startup struct {
	Pairing       bool                 `json:"pairing,omitempty"`
	PairTarget    *contract.PairTarget `json:"pairTarget,omitempty"`
	Version       string               `json:"version"`
	Mode          string               `json:"mode"`
	BrokerAddress string               `json:"brokerAddress"`
	BrokerToken   string               `json:"brokerToken"`
	Identity      string               `json:"identity"`
	Token         string               `json:"token"`
	ShareID       string               `json:"shareId"`
	InstanceID    string               `json:"instanceId"`
	Port          int                  `json:"port"`
	Point         model.AccessPoint    `json:"point,omitempty"`
}

type event struct {
	Pairing      bool                     `json:"pairing,omitempty"`
	PairView     *contract.PairView       `json:"pairView,omitempty"`
	PairProgress *contract.PairProgress   `json:"pairProgress,omitempty"`
	Kind         string                   `json:"kind"`
	Address      string                   `json:"address,omitempty"`
	Port         int                      `json:"port,omitempty"`
	Token        string                   `json:"token,omitempty"`
	Clients      int                      `json:"clients,omitempty"`
	Error        string                   `json:"error,omitempty"`
	Epoch        uint64                   `json:"epoch,omitempty"`
	Revision     string                   `json:"revision,omitempty"`
	Info         *vpncontract.SessionInfo `json:"info,omitempty"`
	Sequence     uint64                   `json:"sequence,omitempty"`
	ID           uint64                   `json:"id,omitempty"`
	Snapshot     *discovery.Snapshot      `json:"snapshot,omitempty"`
	Status       *discovery.Status        `json:"status,omitempty"`
}

type command struct {
	PairCommand  *contract.PairCommand   `json:"pairCommand,omitempty"`
	Operation    string                  `json:"operation"`
	ID           uint64                  `json:"id,omitempty"`
	Announcement *discovery.Announcement `json:"announcement,omitempty"`
	Interfaces   []discovery.Interface   `json:"interfaces,omitempty"`
}

type processServer struct {
	pairing bool
	rpcMu   sync.Mutex
	rpc     map[uint64]chan event
	seq     atomic.Uint64
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	broker  *broker
	events  chan event
	done    chan struct{}
	waitErr error
	waitMu  sync.RWMutex
	writeMu ctxlock.Mutex
	clients atomic.Int64
	port    int
	closed  atomic.Bool
}

var _ relay.ServerInstance = (*processServer)(nil)

// FindExecutable locates the separately packaged relay component.
func FindExecutable() string {
	if p := strings.TrimSpace(os.Getenv("EASYCONNECT_RELAY")); p != "" && regularFile(p) {
		return p
	}
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	name := "connect-hub-relay"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	for _, p := range []string{filepath.Join(filepath.Dir(exe), "core", name), filepath.Join(filepath.Dir(exe), name)} {
		if regularFile(p) {
			return p
		}
	}
	return ""
}

func regularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// Factory returns a ServerFactory that refuses to fall back to an in-process
// listener when the optional component is missing or incompatible.
func Factory(executable string) relay.ServerFactory {
	return func(opts relay.ServerOptions) (relay.ServerInstance, error) {
		if executable == "" {
			return nil, errors.New("缺少局域网分享组件 connect-hub-relay")
		}
		server, err := start(opts, executable)
		if err != nil {
			return nil, err
		}
		return server, nil
	}
}

func start(opts relay.ServerOptions, executable string) (*processServer, error) {
	startupCtx := opts.StartupContext
	if startupCtx == nil {
		startupCtx = context.Background()
	}
	if err := startupCtx.Err(); err != nil {
		return nil, err
	}
	if opts.Source == nil || opts.Identity == nil || opts.Token == "" || opts.ShareID == "" {
		return nil, errors.New("分享进程启动配置不完整")
	}
	ctx, cancel := context.WithTimeout(startupCtx, 4*time.Second)
	defer cancel()
	probe := newCommandContext(ctx, executable, "--protocol-version")
	out, err := probe.Output()
	if startupCtx.Err() != nil {
		return nil, startupCtx.Err()
	}
	if err != nil || strings.TrimSpace(string(out)) != ProtocolVersion {
		return nil, errors.New("局域网分享组件版本不兼容，请重新安装完整程序")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("本机分享数据通道无法启动：%w", err)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		_ = listener.Close()
		return nil, err
	}
	token := base64.RawURLEncoding.EncodeToString(secret)
	b := newBroker(listener, token, opts.Source)
	b.devices = opts.DeviceStore
	b.shareID = opts.ShareID
	identity, err := relay.EncodeIdentity(opts.Identity)
	if err != nil {
		_ = b.Close()
		return nil, err
	}
	instance := opts.ServerInstanceID
	if instance == "" {
		instance = "relay"
	}
	start := startup{Version: ProtocolVersion, Mode: "share", BrokerAddress: listener.Addr().String(), BrokerToken: token, Pairing: opts.DeviceStore != nil,
		Identity: identity, Token: opts.Token, ShareID: opts.ShareID, InstanceID: instance, Port: opts.Port}
	cmd := newCommand(executable)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		_ = b.Close()
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = b.Close()
		return nil, err
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		_ = b.Close()
		return nil, fmt.Errorf("局域网分享组件无法启动：%w", err)
	}
	ps := &processServer{cmd: cmd, stdin: stdin, broker: b, events: make(chan event, 8), done: make(chan struct{}), rpc: make(map[uint64]chan event)}
	go ps.readEvents(stdout)
	go ps.wait()
	// Closing stdin interrupts a blocked startup write. This callback is only
	// armed during initialization; the running child owns a separate lifetime.
	stopStartup := context.AfterFunc(startupCtx, func() { _ = stdin.Close() })
	defer stopStartup()
	if err := json.NewEncoder(stdin).Encode(start); err != nil {
		_ = ps.terminate()
		if startupCtx.Err() != nil {
			return nil, startupCtx.Err()
		}
		return nil, fmt.Errorf("局域网分享组件握手失败：%w", err)
	}
	select {
	case e := <-ps.events:
		if startupCtx.Err() != nil {
			_ = ps.terminate()
			return nil, startupCtx.Err()
		}
		if e.Kind != "ready" || e.Port <= 0 || e.Port > 65535 {
			_ = ps.terminate()
			if e.Error != "" {
				return nil, errors.New(e.Error)
			}
			return nil, errors.New("局域网分享组件返回无效握手")
		}
		ps.port = e.Port
		ps.pairing = e.Pairing
		return ps, nil
	case <-startupCtx.Done():
		_ = ps.terminate()
		return nil, startupCtx.Err()
	case <-ps.done:
		ps.waitMu.RLock()
		waitErr := ps.waitErr
		ps.waitMu.RUnlock()
		_ = b.Close()
		return nil, fmt.Errorf("局域网分享组件启动失败：%w", waitErr)
	case <-time.After(8 * time.Second):
		_ = ps.terminate()
		return nil, errors.New("局域网分享组件启动超时")
	}
}

func (p *processServer) readEvents(r io.Reader) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1024), 256<<10)
	for scanner.Scan() {
		var e event
		if json.Unmarshal(scanner.Bytes(), &e) != nil {
			continue
		}
		if e.Kind == "clients" {
			p.clients.Store(int64(e.Clients))
		}
		if e.Kind == "pair-result" {
			p.rpcMu.Lock()
			ch := p.rpc[e.ID]
			p.rpcMu.Unlock()
			if ch != nil {
				select {
				case ch <- e:
				default:
				}
			}
			continue
		}
		select {
		case p.events <- e:
		default:
		}
	}
}

func (p *processServer) wait() {
	err := p.cmd.Wait()
	p.waitMu.Lock()
	p.waitErr = err
	p.waitMu.Unlock()
	close(p.done)
}

func (p *processServer) Port() int { return p.port }

func (p *processServer) ActiveClients() int { return int(p.clients.Load()) }

func (p *processServer) Done() <-chan struct{} { return p.done }

func (p *processServer) RevokeAll() { _ = p.send(command{Operation: "revoke"}) }

func (p *processServer) Close(ctx context.Context) error {
	if !p.closed.CompareAndSwap(false, true) {
		return nil
	}
	_ = p.send(command{Operation: "stop"})
	select {
	case <-p.done:
	case <-ctx.Done():
		_ = p.cmd.Process.Kill()
		<-p.done
	case <-time.After(5 * time.Second):
		_ = p.cmd.Process.Kill()
		<-p.done
	}
	brokerErr := p.broker.Close()
	p.waitMu.RLock()
	err := p.waitErr
	p.waitMu.RUnlock()
	if ctx.Err() != nil {
		return errors.Join(ctx.Err(), brokerErr)
	}
	if err != nil {
		return errors.Join(fmt.Errorf("局域网分享组件退出异常：%w", err), brokerErr)
	}
	return brokerErr
}

func (p *processServer) terminate() error {
	// Initialization may have failed because the child stopped reading stdin;
	// termination must not wait for another write to that same pipe.
	_ = p.stdin.Close()
	_ = p.cmd.Process.Kill()
	select {
	case <-p.done:
	case <-time.After(3 * time.Second):
	}
	return p.broker.Close()
}

func (p *processServer) send(c command) error {
	return p.sendContext(context.Background(), c)
}

func (p *processServer) sendContext(ctx context.Context, c command) error {
	if err := p.writeMu.LockContext(ctx); err != nil {
		return err
	}
	defer p.writeMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	return json.NewEncoder(p.stdin).Encode(c)
}

// ChildMain is called only by cmd/app-relay. stdin/stdout are the bounded
// control channel; all byte streams use the authenticated loopback broker.
func ChildMain(in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 1024), 64<<10)
	if !scanner.Scan() {
		return errors.New("分享进程缺少启动配置")
	}
	var cfg startup
	if err := json.Unmarshal(scanner.Bytes(), &cfg); err != nil || cfg.Version != ProtocolVersion {
		return errors.New("分享进程配置无效或版本不兼容")
	}
	if cfg.Mode == "import" {
		return runImportedChild(cfg, scanner, out)
	}
	if cfg.Mode == "pair" {
		return runPairChild(cfg, scanner, out)
	}
	if cfg.Mode == "discovery" {
		return runDiscoveryChild(scanner, out)
	}
	if cfg.Mode != "share" {
		return errors.New("未知 relay 进程模式")
	}
	if cfg.Port < 0 || cfg.Port > 65535 || cfg.InstanceID == "" || cfg.BrokerToken == "" {
		return errors.New("分享进程配置字段无效")
	}
	identity, err := relay.DecodeIdentity(cfg.Identity)
	if err != nil {
		return fmt.Errorf("分享身份无效：%w", err)
	}
	source := newRemoteSource(cfg.BrokerAddress, cfg.BrokerToken)
	defer source.Close()
	var devices contract.DeviceStore
	if cfg.Pairing {
		devices = remoteDeviceStore{source, cfg.ShareID}
	}
	server, err := relay.StartServer(relay.ServerOptions{Identity: identity, Source: source,
		Token: cfg.Token, ShareID: cfg.ShareID, ServerInstanceID: cfg.InstanceID, Port: cfg.Port, DeviceStore: devices})
	if err != nil {
		return err
	}
	write := func(e event) error { return json.NewEncoder(out).Encode(e) }
	if err := write(event{Kind: "ready", Address: server.ListenAddress(), Port: server.Port(), Pairing: server.PairingSupported()}); err != nil {
		_ = server.Close(context.Background())
		return err
	}
	stop := make(chan command, 1)
	go func() {
		for scanner.Scan() {
			var c command
			if json.Unmarshal(scanner.Bytes(), &c) == nil {
				stop <- c
			}
		}
		select {
		case stop <- command{Operation: "stop"}:
		default:
		}
	}()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case c := <-stop:
			switch c.Operation {
			case "pair-control":
				if c.PairCommand == nil {
					continue
				}
				ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
				v, err := server.PairControl(ctx, *c.PairCommand)
				cancel()
				e := event{Kind: "pair-result", ID: c.ID, PairView: &v}
				if err != nil {
					e.Error = err.Error()
				}
				if write(e) != nil {
					_ = server.Close(context.Background())
					return errors.New("pair control channel closed")
				}
			case "revoke":
				server.RevokeAll()
			case "stop":
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				err := server.Close(ctx)
				cancel()
				if err != nil {
					_ = write(event{Kind: "error", Error: err.Error()})
					return err
				}
				_ = write(event{Kind: "stopped"})
				return nil
			}
		case <-ticker.C:
			if err := write(event{Kind: "clients", Clients: server.ActiveClients()}); err != nil {
				_ = server.Close(context.Background())
				return err
			}
		}
	}
}

type broker struct {
	devices contract.DeviceStore
	shareID string
	server  *http.Server
	ln      net.Listener
	token   string
	source  contract.Source
	streams *streamGroup
	cancel  context.CancelFunc
	done    chan struct{}
}

func newBroker(ln net.Listener, token string, source contract.Source) *broker {
	ctx, cancel := context.WithCancel(context.Background())
	b := &broker{ln: ln, token: token, source: source, streams: newStreamGroup(), cancel: cancel, done: make(chan struct{})}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", b.health)
	mux.HandleFunc("/snapshot", b.snapshot)
	mux.HandleFunc("/dns", b.dns)
	mux.HandleFunc("/dial", b.dial)
	mux.HandleFunc("/devices", b.deviceRecords)
	b.server = &http.Server{Handler: mux, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 8 * time.Second, WriteTimeout: 8 * time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 8 << 10,
		BaseContext: func(net.Listener) context.Context { return ctx }}
	go func() { _ = b.server.Serve(ln) }()
	go func() {
		defer close(b.done)
		for {
			select {
			case <-ctx.Done():
				return
			case <-source.Done():
				b.streams.Close()
				return
			case <-source.Changes():
				b.streams.Retire()
			}
		}
	}()
	return b
}

func (b *broker) authorized(w http.ResponseWriter, r *http.Request) bool {
	if r.RemoteAddr == "" || !strings.HasPrefix(r.RemoteAddr, "127.0.0.1:") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if len(got) != len(b.token) || subtle.ConstantTimeCompare([]byte(got), []byte(b.token)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func (b *broker) health(w http.ResponseWriter, r *http.Request) {
	if !b.authorized(w, r) {
		return
	}
	select {
	case <-b.source.Done():
		http.Error(w, "source ended", http.StatusGone)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (b *broker) snapshot(w http.ResponseWriter, r *http.Request) {
	if !b.authorized(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	snap, err := b.source.Snapshot(r.Context())
	if err != nil {
		http.Error(w, "snapshot unavailable", http.StatusServiceUnavailable)
		return
	}
	data, err := json.Marshal(snap)
	if err != nil || len(data) > maxBrokerMessage {
		http.Error(w, "snapshot too large", http.StatusRequestEntityTooLarge)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}

func (b *broker) dns(w http.ResponseWriter, r *http.Request) {
	if !b.authorized(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	query, err := io.ReadAll(io.LimitReader(r.Body, int64(relay.MaxDNSBody)+1))
	if err != nil || len(query) == 0 || len(query) > relay.MaxDNSBody {
		http.Error(w, "query too large", http.StatusRequestEntityTooLarge)
		return
	}
	answer, err := b.source.ExchangeDNS(r.Context(), r.Header.Get("X-Resource-Revision"), query)
	if err != nil {
		http.Error(w, "DNS unavailable", http.StatusServiceUnavailable)
		return
	}
	if len(answer) > relay.MaxDNSBody {
		http.Error(w, "answer too large", http.StatusRequestEntityTooLarge)
		return
	}
	_, _ = w.Write(answer)
}

func (b *broker) dial(w http.ResponseWriter, r *http.Request) {
	if !b.authorized(w, r) {
		return
	}
	if r.Method != http.MethodConnect {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), relay.DialTimeout)
	upstream, err := b.source.DialVPN(ctx, r.Header.Get("X-Resource-Revision"), r.Header.Get("X-Relay-Target"))
	cancel()
	if err != nil {
		http.Error(w, "dial denied", http.StatusForbidden)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		cancel()
		_ = upstream.Close()
		http.Error(w, "unsupported", http.StatusInternalServerError)
		return
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		cancel()
		_ = upstream.Close()
		return
	}
	if _, err := rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		cancel()
		_ = conn.Close()
		_ = upstream.Close()
		return
	}
	if err := rw.Flush(); err != nil {
		cancel()
		_ = conn.Close()
		_ = upstream.Close()
		return
	}
	if rw.Reader.Buffered() > 0 {
		conn = &prefixConn{Conn: conn, r: rw.Reader}
	}
	_ = conn.SetDeadline(time.Time{})
	b.streams.Bridge(r.Context(), conn, upstream)
}

type prefixConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *prefixConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func bridge(ctx context.Context, left, right net.Conn) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(left, right); done <- struct{}{} }()
	go func() { _, _ = io.Copy(right, left); done <- struct{}{} }()
	remaining := 2
	select {
	case <-ctx.Done():
	case <-done:
		remaining--
	}
	_ = left.Close()
	_ = right.Close()
	for range remaining {
		<-done
	}
}

func (b *broker) Close() error {
	b.cancel()
	b.streams.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := b.server.Shutdown(ctx)
	_ = b.server.Close()
	<-b.done
	return err
}

type remoteSource struct {
	address   string
	token     string
	client    *http.Client
	changes   chan struct{}
	done      chan struct{}
	watchDone chan struct{}
	ctx       context.Context
	cancel    context.CancelFunc
	once      sync.Once
	mu        sync.Mutex
	last      contract.SourceSnapshot
}

func newRemoteSource(address, token string) *remoteSource {
	ctx, cancel := context.WithCancel(context.Background())
	base := &remoteSource{address: address, token: token, changes: make(chan struct{}, 1), done: make(chan struct{}), watchDone: make(chan struct{}), ctx: ctx, cancel: cancel,
		client: &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}}
	go base.watch()
	return base
}

func newBrokerClient(address, token string) *remoteSource {
	return &remoteSource{address: address, token: token,
		client: &http.Client{Timeout: 6 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}}
}

func (s *remoteSource) endpoint(path string) string { return "http://" + s.address + path }

func (s *remoteSource) request(ctx context.Context, method, path string, body io.Reader, revision string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, s.endpoint(path), body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	if revision != "" {
		req.Header.Set("X-Resource-Revision", revision)
	}
	return s.client.Do(req)
}

func (s *remoteSource) Snapshot(ctx context.Context) (contract.SourceSnapshot, error) {
	resp, err := s.request(ctx, http.MethodGet, "/snapshot", nil, "")
	if err != nil {
		return contract.SourceSnapshot{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return contract.SourceSnapshot{}, fmt.Errorf("source broker returned %s", resp.Status)
	}
	var snap contract.SourceSnapshot
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxBrokerMessage+1))
	if err := dec.Decode(&snap); err != nil {
		return contract.SourceSnapshot{}, err
	}
	if err := snap.Validate(); err != nil {
		return contract.SourceSnapshot{}, err
	}
	return snap, nil
}

func (s *remoteSource) DialVPN(ctx context.Context, revision, target string) (net.Conn, error) {
	if revision == "" || target == "" {
		return nil, errors.New("strict dial requires a resource revision and target")
	}
	addr, err := net.ResolveTCPAddr("tcp4", s.address)
	if err != nil {
		return nil, err
	}
	conn, err := (&net.Dialer{Timeout: relay.DialTimeout}).DialContext(ctx, "tcp4", addr.String())
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	request := "CONNECT /dial HTTP/1.1\r\nHost: " + s.address + "\r\nAuthorization: Bearer " + s.token + "\r\nX-Resource-Revision: " + revision + "\r\nX-Relay-Target: " + target + "\r\n\r\n"
	if _, err := io.WriteString(conn, request); err != nil {
		_ = conn.Close()
		return nil, err
	}
	br := bufio.NewReaderSize(conn, 4096)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, fmt.Errorf("strict dial refused: %s", resp.Status)
	}
	if err := ctx.Err(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	if br.Buffered() > 0 {
		return &prefixConn{Conn: conn, r: br}, nil
	}
	return conn, nil
}

func (s *remoteSource) ExchangeDNS(ctx context.Context, revision string, query []byte) ([]byte, error) {
	if len(query) == 0 || len(query) > relay.MaxDNSBody {
		return nil, errors.New("DNS query exceeds limit")
	}
	resp, err := s.request(ctx, http.MethodPost, "/dns", strings.NewReader(string(query)), revision)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DNS broker returned %s", resp.Status)
	}
	answer, err := io.ReadAll(io.LimitReader(resp.Body, int64(relay.MaxDNSBody)+1))
	if err != nil || len(answer) > relay.MaxDNSBody {
		return nil, errors.New("DNS response exceeds limit")
	}
	return answer, nil
}

func (s *remoteSource) Changes() <-chan struct{} { return s.changes }
func (s *remoteSource) Done() <-chan struct{}    { return s.done }
func (s *remoteSource) Close() error {
	s.once.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
		if s.done != nil {
			close(s.done)
		}
	})
	s.client.CloseIdleConnections()
	if s.watchDone != nil {
		<-s.watchDone
	}
	return nil
}

func (s *remoteSource) watch() {
	defer close(s.watchDone)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	healthTicker := time.NewTicker(time.Second)
	defer healthTicker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(s.ctx, 2*time.Second)
			snap, err := s.Snapshot(ctx)
			cancel()
			if err == nil {
				s.mu.Lock()
				changed := s.last.Revision != "" && (s.last.Epoch != snap.Epoch || s.last.Revision != snap.Revision)
				s.last = snap
				s.mu.Unlock()
				if changed {
					select {
					case s.changes <- struct{}{}:
					default:
					}
				}
			}
		case <-healthTicker.C:
			ctx, cancel := context.WithTimeout(s.ctx, time.Second)
			resp, err := s.request(ctx, http.MethodGet, "/health", nil, "")
			cancel()
			if err != nil {
				s.once.Do(func() { close(s.done) })
				return
			}
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusGone {
				s.once.Do(func() { close(s.done) })
				return
			}
		}
	}
}

// Wire helpers are kept here so the command-line mode and parent use one
// versioned DTO definition.
func ProtocolVersionString() string { return ProtocolVersion }
