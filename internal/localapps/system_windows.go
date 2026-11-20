package localapps

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"sync"

	"github.com/qy/easyconnect/internal/netpolicy"
	"github.com/qy/easyconnect/internal/proxy"
	"github.com/qy/easyconnect/internal/vpn"
	"github.com/qy/easyconnect/internal/wincapture"
)

type systemSession interface {
	Done() <-chan struct{}
	Err() error
	OriginalDial(context.Context, string, string) (net.Conn, error)
	EnableSystem(context.Context, wincapture.Upstream) (func() error, error)
}
type systemScope struct {
	stop     func() error
	release  func()
	dns      *dnsBinding
	startErr error
}
type windowsSystemCapture struct {
	ownershipMu sync.RWMutex
	known       []netpolicy.Range
	mu          sync.Mutex
	dns         *dnsPool
	acquire     func(context.Context, string, wincapture.Config) (systemSession, func(), error)
	scopes      map[string]systemScope
	order       []string
	proxy       *proxy.Server
	upstream    wincapture.Upstream
	dial        DialFunc
	life        context.Context
	cancel      context.CancelFunc
	done        chan struct{}
	err         error
	cleanupErr  error
	closed      bool
}

func (m *Manager) StartSystemCapture(ctx context.Context, configs []CaptureConfig, dial DialFunc) (SystemCapture, error) {
	run, err := startSystemCapture(ctx, &m.dns, configs, dial, func(ctx context.Context, key string, config wincapture.Config) (systemSession, func(), error) {
		return wincapture.Acquire(ctx, key, config)
	})
	if run == nil {
		return nil, err
	}
	return run, err
}

func startSystemCapture(ctx context.Context, dns *dnsPool, configs []CaptureConfig, dial DialFunc, acquire func(context.Context, string, wincapture.Config) (systemSession, func(), error)) (*windowsSystemCapture, error) {
	if len(configs) == 0 || dial == nil {
		return nil, errors.New("没有可接管的在线网关")
	}
	for _, config := range configs {
		if err := checkSystemConfig(config); err != nil {
			return nil, err
		}
	}
	life, cancel := context.WithCancel(context.Background())
	r := &windowsSystemCapture{dns: dns, acquire: acquire, scopes: map[string]systemScope{}, dial: dial, life: life, cancel: cancel, done: make(chan struct{})}
	for _, config := range configs {
		if err := r.Add(ctx, config); err != nil {
			if cleanupErr := r.Close(); cleanupErr != nil {
				return r, errors.Join(err, cleanupErr)
			}
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		if cleanupErr := r.Close(); cleanupErr != nil {
			return r, errors.Join(err, cleanupErr)
		}
		return nil, err
	}
	return r, nil
}

func checkSystemConfig(config CaptureConfig) error {
	if config.Key == "" || config.Active == nil || !config.Active() {
		return errors.New("系统接管需要在线会话")
	}
	if _, err := wincapture.ResourcePrefixes(config.Networks); err != nil {
		return err
	}
	if len(config.Domains) > 0 && (config.MappedDNS == nil || config.SelectDNS == nil || config.BeginPublication == nil || config.ConfirmAliases == nil) {
		return errors.New("该网关尚不具备系统 DNS 映射能力，请继续使用显式代理")
	}
	if len(config.Networks) == 0 && len(config.Domains) == 0 {
		return errors.New("网关没有可接管的资源")
	}
	return nil
}

func (r *windowsSystemCapture) Add(ctx context.Context, config CaptureConfig) error {
	if err := checkSystemConfig(config); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return net.ErrClosed
	}
	if scope, ok := r.scopes[config.Key]; ok {
		return scope.startErr
	}
	binding, err := r.dns.acquireContext(ctx, config)
	if err != nil {
		return err
	}
	keep := false
	defer func() {
		if !keep && binding != nil {
			binding.release()
		}
	}()
	if binding != nil {
		ctx = context.WithValue(ctx, dnsContextKey{}, binding)
	}
	session, release, err := r.acquire(ctx, config.Key, windowsConfig(ctx, config))
	if err != nil {
		return err
	}
	defer func() {
		if !keep {
			release()
		}
	}()
	if r.proxy == nil {
		var secret [32]byte
		if _, err := rand.Read(secret[:]); err != nil {
			return err
		}
		password := hex.EncodeToString(secret[:])
		r.proxy = proxy.New(proxy.Options{Addr: "127.0.0.1:0", Auth: &proxy.Auth{Username: "system", Credential: password}, Context: r.life, SOCKSOnly: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				r.ownershipMu.RLock()
				known := append([]netpolicy.Range(nil), r.known...)
				r.ownershipMu.RUnlock()
				return r.dial(vpn.WithCapturedOwnership(vpn.WithOriginalDial(ctx, session.OriginalDial), known), network, address)
			}})
		if err := r.proxy.Start(); err != nil {
			r.proxy = nil
			return err
		}
		r.upstream = wincapture.Upstream{Address: r.proxy.Addr().String(), Username: "system", Password: password}
	}
	r.ownershipMu.Lock()
	r.known = append(r.known, config.Networks...)
	r.ownershipMu.Unlock()
	stop, err := session.EnableSystem(ctx, r.upstream)
	if err == nil {
		err = ctx.Err()
	}
	if err == nil && !config.Active() {
		err = errors.New("启用期间 VPN 会话已变化")
	}
	if err != nil {
		if stop != nil {
			if cleanupErr := stop(); cleanupErr != nil {
				// Keep the session and DNS references for a later cleanup retry.
				err = errors.Join(err, cleanupErr)
				r.scopes[config.Key] = systemScope{stop: stop, release: release, dns: binding, startErr: err}
				r.order = append(r.order, config.Key)
				keep = true
			}
		}
		return err
	}
	r.scopes[config.Key] = systemScope{stop: stop, release: release, dns: binding}
	r.order = append(r.order, config.Key)
	keep = true
	go func() {
		select {
		case <-r.done:
			return
		case <-session.Done():
			r.mu.Lock()
			if !r.closed {
				r.err = errors.Join(r.err, errors.New("系统网络助手已停止"), session.Err())
			}
			r.mu.Unlock()
			_ = r.Close()
		}
	}()
	return nil
}

func (r *windowsSystemCapture) Done() <-chan struct{} { return r.done }
func (r *windowsSystemCapture) Err() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return errors.Join(r.err, r.cleanupErr)
}
func (r *windowsSystemCapture) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed {
		r.closed = true
		r.cancel()
		defer close(r.done)
	}
	var cleanupErr error
	for i := len(r.order) - 1; i >= 0; i-- {
		key := r.order[i]
		scope, ok := r.scopes[key]
		if !ok {
			continue
		}
		if err := scope.stop(); err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
			continue
		}
		scope.release()
		if scope.dns != nil {
			scope.dns.release()
		}
		delete(r.scopes, key)
	}
	if r.proxy != nil {
		if err := r.proxy.Close(); err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
		} else {
			r.proxy = nil
		}
	}
	r.cleanupErr = cleanupErr
	return cleanupErr
}
