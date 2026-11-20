package localapps

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"slices"
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
	config   CaptureConfig
	stop     func() error
	release  func()
	cancel   context.CancelFunc
	dns      *dnsBinding
	startErr error
}
type windowsSystemCapture struct {
	ownershipMu sync.RWMutex
	known       map[netpolicy.Range]struct{}
	mu          sync.Mutex
	dns         *dnsPool
	acquire     func(context.Context, string, wincapture.Config) (systemSession, func(), error)
	scopes      map[string]*systemScope
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
	r := &windowsSystemCapture{dns: dns, acquire: acquire, scopes: map[string]*systemScope{}, known: map[netpolicy.Range]struct{}{}, dial: dial, life: life, cancel: cancel, done: make(chan struct{})}
	r.mu.Lock()
	for _, config := range configs {
		if err := r.addLocked(ctx, config); err != nil {
			r.mu.Unlock()
			if cleanupErr := r.Close(); cleanupErr != nil {
				return r, errors.Join(err, cleanupErr)
			}
			return nil, err
		}
	}
	r.mu.Unlock()
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

func (r *windowsSystemCapture) Reconcile(ctx context.Context, configs []CaptureConfig) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return net.ErrClosed
	}
	ready := make(map[string]CaptureConfig, len(configs))
	var result error
	for _, config := range configs {
		if err := ctx.Err(); err != nil {
			return errors.Join(result, err)
		}
		if config.Guard && r.scopes[config.Key] == nil {
			// Existing routes can guard an offline owner. The dialer and DNS
			// selector independently reject the expired VPN generation.
			covered := false
			for _, scope := range r.scopes {
				if scope.startErr == nil && coversSystemScope(scope.config, config) {
					covered = true
					break
				}
			}
			if covered {
				continue
			}
		}
		if err := r.addLocked(ctx, config); err != nil {
			result = errors.Join(result, err)
			continue
		}
		ready[config.Key] = config
	}
	for key, scope := range r.scopes {
		if _, keep := ready[key]; keep {
			continue
		}
		for _, replacement := range ready {
			if coversSystemScope(replacement, scope.config) {
				result = errors.Join(result, r.removeLocked(key, scope))
				break
			}
		}
	}
	return result
}

func coversSystemScope(current, previous CaptureConfig) bool {
	if current.Identity.GatewayID != previous.Identity.GatewayID {
		return false
	}
	for _, network := range previous.Networks {
		if !slices.Contains(current.Networks, network) {
			return false
		}
	}
	for _, domain := range previous.Domains {
		if !slices.Contains(current.Domains, domain) {
			return false
		}
	}
	return true
}

func (r *windowsSystemCapture) addLocked(ctx context.Context, config CaptureConfig) error {
	if err := checkSystemConfig(config); err != nil {
		return err
	}
	if scope := r.scopes[config.Key]; scope != nil {
		if scope.startErr == nil {
			return nil
		}
		if err := r.removeLocked(config.Key, scope); err != nil {
			return errors.Join(scope.startErr, err)
		}
	}
	scope := &systemScope{config: config, cancel: func() {}}
	if config.Guard {
		life, cancel := context.WithCancel(r.life)
		scope.cancel = cancel
		active := config.Active
		config.Active = func() bool { return life.Err() == nil && active() }
	}
	keep := false
	defer func() {
		if !keep {
			scope.cancel()
		}
	}()
	binding, err := r.dns.acquireContext(ctx, config)
	if err != nil {
		return err
	}
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
				known := make([]netpolicy.Range, 0, len(r.known))
				for network := range r.known {
					known = append(known, network)
				}
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
	for _, network := range config.Networks {
		r.known[network] = struct{}{}
	}
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
				scope.stop, scope.release, scope.dns, scope.startErr = stop, release, binding, err
				r.scopes[config.Key] = scope
				r.order = append(r.order, config.Key)
				keep = true
			}
		}
		return err
	}
	scope.stop, scope.release, scope.dns = stop, release, binding
	r.scopes[config.Key] = scope
	r.order = append(r.order, config.Key)
	keep = true
	go func() {
		select {
		case <-r.done:
			return
		case <-session.Done():
			r.mu.Lock()
			if r.closed || r.scopes[config.Key] != scope {
				r.mu.Unlock()
				return
			}
			r.err = errors.Join(r.err, errors.New("系统网络助手已停止"), session.Err())
			r.mu.Unlock()
			_ = r.Close()
		}
	}()
	return nil
}

func (r *windowsSystemCapture) removeLocked(key string, scope *systemScope) error {
	if err := scope.stop(); err != nil {
		return err
	}
	delete(r.scopes, key)
	r.order = slices.DeleteFunc(r.order, func(value string) bool { return value == key })
	scope.cancel()
	scope.release()
	if scope.dns != nil {
		scope.dns.release()
	}
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
		cleanupErr = errors.Join(cleanupErr, r.removeLocked(key, scope))
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
