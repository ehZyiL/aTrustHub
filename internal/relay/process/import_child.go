package process

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ehzyil/connect-hub/internal/relay"
	"github.com/ehzyil/connect-hub/internal/relay/adapter"
	vpncontract "github.com/ehzyil/connect-hub/internal/vpn/contract"
)

type versionedSession interface {
	ResourceVersion() (uint64, string)
}

func runImportedChild(cfg startup, scanner *bufio.Scanner, out io.Writer) error {
	if cfg.Point.Protocol != "lan_relay" || cfg.Point.Relay == nil || cfg.Token == "" {
		return errors.New("导入分享配置缺少协议身份或口令")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	connector := adapter.NewConnector(adapter.Options{Dial: relay.DirectDialer})
	session, err := connector(ctx, cfg.Point, vpncontract.Credentials{Login: cfg.Token})
	if err != nil {
		return err
	}
	defer session.Close()
	strict, ok := session.(vpncontract.StrictSession)
	if !ok {
		return errors.New("导入的分享会话不支持严格 VPN 拨号")
	}
	watcher, ok := session.(vpncontract.SessionWatcher)
	if !ok {
		return errors.New("导入的分享会话缺少生命周期通知")
	}
	versioned, ok := session.(versionedSession)
	if !ok {
		return errors.New("导入的分享会话缺少资源版本")
	}
	info := session.Info()
	epoch, revision := versioned.ResourceVersion()
	if info.Resources == nil || revision == "" {
		return errors.New("导入的分享会话没有有效资源快照")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		_ = listener.Close()
		return err
	}
	brokerToken := base64.RawURLEncoding.EncodeToString(secret)
	broker := newImportBroker(listener, brokerToken, strict, session, versioned)
	defer broker.Close()
	var outputMu sync.Mutex
	write := func(e event) error {
		outputMu.Lock()
		defer outputMu.Unlock()
		return json.NewEncoder(out).Encode(e)
	}
	if err := write(event{Kind: "ready", Address: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port,
		Token: brokerToken, Epoch: epoch, Revision: revision, Info: &info}); err != nil {
		return err
	}
	stop := make(chan command, 4)
	go func() {
		for scanner.Scan() {
			var c command
			if json.Unmarshal(scanner.Bytes(), &c) == nil {
				stop <- c
			}
		}
		stop <- command{Operation: "stop"}
	}()
	var updates <-chan vpncontract.SessionUpdate
	if updater, ok := session.(vpncontract.SessionUpdater); ok {
		updates = updater.Updates()
	}
	for {
		select {
		case c := <-stop:
			if c.Operation == "stop" {
				cancel()
				_ = session.Close()
				return nil
			}
		case update, open := <-updates:
			if !open {
				updates = nil
				continue
			}
			epoch, revision = versioned.ResourceVersion()
			info := vpncontract.CloneInfo(update.Info)
			if info.Resources == nil || revision == "" {
				continue
			}
			broker.Retire()
			if err := write(event{Kind: "update", Epoch: epoch, Revision: revision, Info: &info, Sequence: update.Sequence}); err != nil {
				return err
			}
		case <-watcher.Done():
			if endErr := watcher.Err(); endErr != nil {
				_ = write(event{Kind: "ended", Error: endErr.Error()})
				return endErr
			}
			_ = write(event{Kind: "ended"})
			return nil
		}
	}
}

type importBroker struct {
	server    *http.Server
	token     string
	strict    vpncontract.StrictSession
	session   vpncontract.Session
	versioned versionedSession
	streams   *streamGroup
	gateMu    sync.Mutex
	revision  string
	closed    chan struct{}
	closeOnce sync.Once
}

func newImportBroker(listener net.Listener, token string, strict vpncontract.StrictSession, session vpncontract.Session, versioned versionedSession) *importBroker {
	b := &importBroker{token: token, strict: strict, session: session, versioned: versioned,
		streams: newStreamGroup(), closed: make(chan struct{})}
	_, b.revision = versioned.ResourceVersion()
	mux := http.NewServeMux()
	mux.HandleFunc("/health", b.health)
	mux.HandleFunc("/dial", b.dial)
	mux.HandleFunc("/dns", b.dns)
	b.server = &http.Server{Handler: mux, ReadHeaderTimeout: 2 * time.Second, MaxHeaderBytes: 8 << 10}
	go func() { _ = b.server.Serve(listener) }()
	go func() {
		select {
		case <-b.closed:
		case <-session.(vpncontract.SessionWatcher).Done():
			b.streams.Close()
		}
	}()
	return b
}

func (b *importBroker) Retire() {
	b.gateMu.Lock()
	_, b.revision = b.versioned.ResourceVersion()
	b.streams.Retire()
	b.gateMu.Unlock()
}

func (b *importBroker) Close() {
	b.closeOnce.Do(func() {
		close(b.closed)
		b.streams.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = b.server.Shutdown(ctx)
		_ = b.server.Close()
	})
}

func (b *importBroker) authorized(w http.ResponseWriter, r *http.Request) bool {
	if !strings.HasPrefix(r.RemoteAddr, "127.0.0.1:") {
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

func (b *importBroker) health(w http.ResponseWriter, r *http.Request) {
	if !b.authorized(w, r) {
		return
	}
	select {
	case <-b.session.(vpncontract.SessionWatcher).Done():
		http.Error(w, "session ended", http.StatusGone)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (b *importBroker) checkRevision(w http.ResponseWriter, r *http.Request) bool {
	_, current := b.versioned.ResourceVersion()
	b.gateMu.Lock()
	active := b.revision
	b.gateMu.Unlock()
	if current == "" || current != active || r.Header.Get("X-Resource-Revision") != current {
		http.Error(w, "stale resource version", http.StatusConflict)
		return false
	}
	return true
}

func (b *importBroker) dial(w http.ResponseWriter, r *http.Request) {
	if !b.authorized(w, r) {
		return
	}
	if r.Method != http.MethodConnect {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if !b.checkRevision(w, r) {
		return
	}
	target := r.Header.Get("X-Relay-Target")
	dialCtx, cancelDial := context.WithTimeout(r.Context(), relay.DialTimeout)
	upstream, err := b.strict.DialVPN(dialCtx, "tcp", target)
	cancelDial()
	if err != nil {
		http.Error(w, "strict dial failed", http.StatusForbidden)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		http.Error(w, "unsupported", http.StatusInternalServerError)
		return
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		_ = upstream.Close()
		return
	}
	if _, err := rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		_ = conn.Close()
		_ = upstream.Close()
		return
	}
	if err := rw.Flush(); err != nil {
		_ = conn.Close()
		_ = upstream.Close()
		return
	}
	if rw.Reader.Buffered() > 0 {
		conn = &prefixConn{Conn: conn, r: rw.Reader}
	}
	_ = conn.SetDeadline(time.Time{})
	b.gateMu.Lock()
	version := b.streams.Version()
	current := b.revision
	b.gateMu.Unlock()
	if current != r.Header.Get("X-Resource-Revision") {
		_ = conn.Close()
		_ = upstream.Close()
		return
	}
	b.streams.BridgeVersion(context.Background(), conn, upstream, version)
}

func (b *importBroker) dns(w http.ResponseWriter, r *http.Request) {
	if !b.authorized(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	if !b.checkRevision(w, r) {
		return
	}
	exchanger, ok := b.session.(vpncontract.DNSExchanger)
	if !ok {
		http.Error(w, "DNS unavailable", http.StatusNotImplemented)
		return
	}
	query, err := io.ReadAll(io.LimitReader(r.Body, int64(relay.MaxDNSBody)+1))
	if err != nil || len(query) == 0 || len(query) > relay.MaxDNSBody {
		http.Error(w, "query too large", http.StatusRequestEntityTooLarge)
		return
	}
	answer, err := exchanger.ExchangeDNS(r.Context(), query)
	if err != nil {
		http.Error(w, "DNS failed", http.StatusForbidden)
		return
	}
	if len(answer) > relay.MaxDNSBody {
		http.Error(w, "answer too large", http.StatusRequestEntityTooLarge)
		return
	}
	_, _ = w.Write(answer)
}
