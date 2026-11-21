package wincapture

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/ehzyil/connect-hub/internal/proxy"
	proxy2 "golang.org/x/net/proxy"
)

func (s *Session) OriginalDial(ctx context.Context, network, address string) (net.Conn, error) {
	runtime := s
	if s.runtime != nil {
		runtime = s.runtime
	}
	if runtime.original == nil {
		return nil, errors.New("原网络出口未就绪")
	}
	return runtime.original.DialContext(ctx, network, address)
}

func (s *Session) EnableSystem(ctx context.Context, upstream Upstream) (func() error, error) {
	if err := upstream.validate(); err != nil {
		return nil, err
	}
	var mu sync.Mutex
	stopped := false
	stop := func() error {
		mu.Lock()
		defer mu.Unlock()
		if stopped {
			return nil
		}
		_, err := s.request(context.Background(), frame{Type: "system_off"})
		if err != nil {
			runtime := s
			if s.runtime != nil {
				runtime = s.runtime
			}
			select {
			case <-runtime.Done():
				if verifier, ok := runtime.file.(interface{ ConfirmCleanup() error }); ok {
					if cleanupErr := verifier.ConfirmCleanup(); cleanupErr != nil {
						err = errors.Join(err, cleanupErr)
					} else {
						err = nil
					}
				}
			default:
			}
		}
		stopped = err == nil
		return err
	}
	// A failed enable may still own rules whose rollback failed. Keep its
	// cleanup capability until the helper acknowledges removal, or its exit
	// and the watchdog's completed cleanup have been independently verified.
	_, err := s.request(ctx, frame{Type: "system_on", Upstream: &upstream})
	return stop, err
}

func (e *engine) startOriginalExit() error {
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return err
	}
	password := hex.EncodeToString(secret[:])
	e.original = proxy.New(proxy.Options{Addr: "127.0.0.1:0", Auth: &proxy.Auth{Username: "original", Credential: password}, Context: e.ctx, SOCKSOnly: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" && network != "tcp4" {
				return nil, errors.New("原出口仅支持 TCP")
			}
			destination, err := netip.ParseAddrPort(address)
			if err != nil || !destination.Addr().Is4() || e.adapter.Contains(destination.Addr()) || netip.MustParsePrefix("198.19.0.0/16").Contains(destination.Addr()) {
				return nil, errors.New("原出口目标无效")
			}
			return originalDial(ctx, "tcp4", address, e.index)
		}})
	if err := e.original.Start(); err != nil {
		return err
	}
	e.originalInfo = Upstream{Address: e.original.Addr().String(), Username: "original", Password: password}
	return nil
}

func (e *engine) enableSystem(id string, upstream *Upstream) error {
	if upstream == nil {
		return errors.New("系统捕获缺少私有入口")
	}
	if err := upstream.validate(); err != nil {
		return err
	}
	e.mu.Lock()
	session := e.sessions[id]
	if session == nil || session.retired || session.system != nil {
		e.mu.Unlock()
		return errors.New("系统接管会话不存在、已退役或已启用")
	}
	if e.system != nil && e.systemInfo != *upstream {
		e.mu.Unlock()
		return errors.New("系统捕获只能使用一个统一资源入口")
	}
	e.mu.Unlock()
	dial, err := proxy.NewSOCKSDialer(upstream.Address, &proxy2.Auth{User: upstream.Username, Password: upstream.Password})
	if err != nil {
		return err
	}
	if err := e.enableRules(session); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.system == nil {
		ctx, cancel := context.WithCancel(e.ctx)
		e.system = &registration{ctx: ctx, cancel: cancel, dial: dial}
		e.systemInfo = *upstream
	}
	session.system = e.system
	return nil
}

func (e *engine) disableSystem(id string) error {
	e.mu.Lock()
	session := e.sessions[id]
	if session == nil {
		e.mu.Unlock()
		return nil
	}
	session.system = nil
	remaining := false
	for _, other := range e.sessions {
		if other.system != nil {
			remaining = true
			break
		}
	}
	if !remaining && e.system != nil {
		e.system.cancel()
		e.system = nil
		e.systemInfo = Upstream{}
	}
	hasApps := false
	for _, app := range e.apps {
		if app.session == id {
			hasApps = true
			break
		}
	}
	e.mu.Unlock()
	if !hasApps {
		return session.rules.Disable()
	}
	return nil
}

func (e *engine) selectSystem(destination netip.Addr) (*registration, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.system == nil {
		return nil, nil
	}
	for _, session := range e.sessions {
		if session.aliases.Contains(destination) {
			entry, ok := session.mappings[destination]
			if session.retired || session.system == nil || !ok || !time.Now().Before(entry.expires) {
				return nil, errors.New("映射不属于有效系统接管会话")
			}
			return e.system, nil
		}
	}
	if e.adapter.Contains(destination) || netip.MustParsePrefix("198.19.0.0/16").Contains(destination) {
		return nil, errors.New("系统捕获目标无效")
	}
	return e.system, nil
}
