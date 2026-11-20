package localapps

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"maps"
	"net"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/qy/easyconnect/internal/capture"
	"github.com/qy/easyconnect/internal/netpolicy"
	"github.com/qy/easyconnect/internal/proxy"
	"github.com/qy/easyconnect/internal/splitdns"
	"github.com/qy/easyconnect/internal/vpn"
	"github.com/qy/easyconnect/internal/workeripc"
	xproxy "golang.org/x/net/proxy"
)

type linuxSystemDNS struct {
	config CaptureConfig
	lease  linuxSystemLease
	id     string
	prefix string
}

type linuxSystemLease interface {
	Start(context.Context, capture.SystemConfig) (capture.SystemState, error)
	Sync(context.Context, capture.SystemConfig) (capture.SystemState, error)
	Publish(context.Context, string, []workeripc.DNSAlias) error
	Ping(context.Context) error
	Close() error
}

func (s linuxSystemDNS) Prefix() string { return s.prefix }
func (s linuxSystemDNS) Publish(ctx context.Context, aliases []workeripc.DNSAlias) error {
	return s.lease.Publish(ctx, s.id, aliases)
}

type linuxSystemCapture struct {
	op        sync.Mutex
	mu        sync.RWMutex
	lease     linuxSystemLease
	config    capture.SystemConfig
	publish   map[string]linuxSystemDNS
	selectDNS func([]byte) (string, func() bool, error)
	known     []netpolicy.Range
	original  *proxy.SOCKSDialer
	proxy     *proxy.Server
	dns       *splitdns.Server
	cancel    context.CancelFunc
	done      chan struct{}
	err       error
	closed    bool
}

func (m *Manager) StartSystemCapture(ctx context.Context, configs []CaptureConfig, dial DialFunc) (SystemCapture, error) {
	if dial == nil {
		return nil, errors.New("缺少系统 TUN 拨号入口")
	}
	life, cancel := context.WithCancel(context.Background())
	r := &linuxSystemCapture{cancel: cancel, done: make(chan struct{})}
	if err := r.start(ctx, life, configs, dial); err != nil {
		if cleanup := r.Close(); cleanup != nil {
			return r, errors.Join(err, cleanup)
		}
		return nil, err
	}
	go r.watch(life)
	return r, nil
}

func (r *linuxSystemCapture) start(ctx, life context.Context, configs []CaptureConfig, dial DialFunc) error {
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return err
	}
	password := hex.EncodeToString(secret[:])
	r.proxy = proxy.New(proxy.Options{Addr: "127.0.0.1:0", Context: life, SOCKSOnly: true,
		Auth: &proxy.Auth{Username: "system", Credential: password},
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			r.mu.RLock()
			original, known := r.original, r.known
			r.mu.RUnlock()
			if original == nil || life.Err() != nil {
				return nil, net.ErrClosed
			}
			return dial(vpn.WithCapturedOwnership(vpn.WithOriginalDial(ctx, original.DialContext), known), network, address)
		}})
	if err := r.proxy.Start(); err != nil {
		return err
	}
	var err error
	r.dns, err = splitdns.Listen(life, r.exchange)
	if err != nil {
		return err
	}
	lease, err := capture.OpenSystem(ctx)
	if err != nil {
		return err
	}
	r.lease = lease
	r.config.Upstream = capture.Upstream{Address: r.proxy.Addr().String(), Username: "system", Password: password}
	r.config.DNSAddress = r.dns.Addr()
	return r.configure(ctx, configs, true)
}

func (r *linuxSystemCapture) Reconcile(ctx context.Context, configs []CaptureConfig) error {
	r.op.Lock()
	defer r.op.Unlock()
	if r.closed {
		return net.ErrClosed
	}
	return r.configure(ctx, configs, false)
}

func (r *linuxSystemCapture) configure(ctx context.Context, configs []CaptureConfig, start bool) error {
	request := capture.SystemConfig{Upstream: r.config.Upstream, DNSAddress: r.config.DNSAddress}
	byID := make(map[string]CaptureConfig, len(configs))
	reservations := map[string]bool{}
	ownPools := map[string]bool{}
	for _, publisher := range r.publish {
		ownPools[publisher.prefix] = true
	}
	var selector func([]byte) (string, func() bool, error)
	online := false
	for _, config := range configs {
		if config.Key == "" || config.Active == nil || !config.Active() {
			return errors.New("系统接管需要有效的会话或离线资源保护")
		}
		if len(config.Domains) > 0 {
			if config.SelectDNS == nil || !config.Guard && (config.MappedDNS == nil || config.BeginPublication == nil || config.ConfirmAliases == nil) {
				return errors.New("该网关尚不具备系统 DNS 映射能力，请使用显式代理")
			}
			selector = config.SelectDNS
		}
		online = online || !config.Guard
		hash := sha256.Sum256([]byte(config.Key + "\x00" + config.Identity.Version))
		id := hex.EncodeToString(hash[:16])
		if _, exists := byID[id]; exists {
			return errors.New("系统接管的网关会话重复")
		}
		byID[id] = config
		request.Resources = append(request.Resources, capture.SystemResource{ID: id, Gateway: config.Gateway, Guard: config.Guard, Networks: config.Networks, Domains: config.Domains})
		request.AliasRanges = append(request.AliasRanges, config.AliasNetworks...)
		for _, pool := range config.ReservedPools {
			if !ownPools[pool] {
				reservations[pool] = true
			}
		}
	}
	if start && !online {
		return errors.New("没有可接管的在线网关")
	}
	if len(request.Resources) == 0 {
		return nil
	}
	slices.SortFunc(request.Resources, func(a, b capture.SystemResource) int { return cmp.Compare(a.ID, b.ID) })
	request.Reserved = slices.Sorted(maps.Keys(reservations))
	var err error
	request.AliasRanges, err = netpolicy.Compact(request.AliasRanges)
	if err != nil {
		return err
	}
	if !start && reflect.DeepEqual(request, r.config) {
		return nil
	}
	known := slices.Clone(r.known)
	for _, resource := range request.Resources {
		known = append(known, resource.Networks...)
	}
	known, err = netpolicy.Compact(known)
	if err != nil {
		return err
	}
	var state capture.SystemState
	if start {
		state, err = r.lease.Start(ctx, request)
	} else {
		state, err = r.lease.Sync(ctx, request)
	}
	if err != nil {
		return err
	}
	original, err := proxy.NewSOCKSDialer(state.Original.Address, &xproxy.Auth{User: state.Original.Username, Password: state.Original.Password})
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.known, r.original = known, original
	r.mu.Unlock()
	publishers := make(map[string]linuxSystemDNS, len(state.Prefixes))
	for id, prefix := range state.Prefixes {
		config := byID[id]
		if config.CheckPublication != nil {
			if err := config.CheckPublication(prefix); err != nil {
				return errors.Join(errors.New("系统 DNS 映射池已变化，请重新登录该网关后启用接管"), err)
			}
		}
		publishers[config.Key] = linuxSystemDNS{config: config, lease: r.lease, id: id, prefix: prefix}
	}
	r.mu.Lock()
	r.config, r.selectDNS, r.publish = request, selector, publishers
	r.mu.Unlock()
	return nil
}

func (r *linuxSystemCapture) exchange(ctx context.Context, packet []byte) ([]byte, error) {
	r.mu.RLock()
	selectDNS := r.selectDNS
	r.mu.RUnlock()
	if selectDNS == nil {
		return nil, errors.New("系统 DNS 未就绪")
	}
	key, current, err := selectDNS(packet)
	if err != nil {
		return nil, err
	}
	r.mu.RLock()
	publisher, ok := r.publish[key]
	r.mu.RUnlock()
	if !ok || current == nil || !current() || !publisher.config.Active() {
		return nil, errors.New("所选网关尚未启用系统 DNS 映射")
	}
	answer, err := exchangeMappedDNS(ctx, publisher, publisher.config, packet)
	if err != nil {
		return nil, err
	}
	r.mu.RLock()
	ready := r.publish[key].id == publisher.id
	r.mu.RUnlock()
	if !ready || !current() || !publisher.config.Active() {
		return nil, errors.New("DNS 查询期间会话或归属已变化")
	}
	return answer, nil
}

func (r *linuxSystemCapture) watch(ctx context.Context) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.dns.Done():
			r.fail(net.ErrClosed)
			return
		case <-tick.C:
			r.op.Lock()
			if r.closed {
				r.op.Unlock()
				return
			}
			err := r.lease.Ping(ctx)
			r.op.Unlock()
			if err != nil {
				r.fail(err)
				return
			}
		}
	}
}

func (r *linuxSystemCapture) fail(err error) {
	r.mu.Lock()
	r.err = errors.Join(r.err, err)
	r.mu.Unlock()
	_ = r.Close()
}

func (r *linuxSystemCapture) Done() <-chan struct{} { return r.done }
func (r *linuxSystemCapture) Err() error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.err
}

func (r *linuxSystemCapture) Close() error {
	r.op.Lock()
	defer r.op.Unlock()
	if !r.closed {
		r.closed = true
		defer close(r.done)
		r.cancel()
		if r.dns != nil {
			_ = r.dns.Close()
		}
		if r.proxy != nil {
			_ = r.proxy.Close()
		}
		r.mu.Lock()
		r.publish, r.original = nil, nil
		r.mu.Unlock()
	}
	if r.lease != nil {
		if err := r.lease.Close(); err != nil {
			return err
		}
		r.lease = nil
	}
	return nil
}
