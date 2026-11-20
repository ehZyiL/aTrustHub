package localapps

import (
	"context"
	"errors"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/qy/easyconnect/internal/netpolicy"
	"github.com/qy/easyconnect/internal/splitdns"
	"github.com/qy/easyconnect/internal/workeripc"
	"golang.org/x/net/idna"
)

type CaptureConfig struct {
	Key       string
	Gateway   string
	Domains   []string
	Exchange  splitdns.ExchangeFunc
	Networks  []netpolicy.Range
	MappedDNS func(context.Context, []byte, string) (workeripc.Message, error)
	Active    func() bool
}

// DNSDomains mirrors the worker's internal-name selection. It never adds the
// root domain or a single-label TLD as a routing policy for the whole computer.
func DNSDomains(resources *workeripc.ResourceSnapshot) ([]string, error) {
	if resources == nil {
		return nil, nil
	}
	var names []string
	names = append(names, resources.InternalDomains...)
	for _, r := range resources.DomainRules {
		names = append(names, r.Domain)
	}
	for _, r := range resources.StaticDNS {
		names = append(names, r.Name)
	}
	seen := map[string]bool{}
	for _, name := range names {
		name = strings.Trim(strings.TrimSpace(name), ".")
		name = strings.TrimPrefix(name, "*.")
		ascii, err := idna.Lookup.ToASCII(name)
		if err != nil {
			return nil, errors.New("网关 DNS 后缀格式不兼容")
		}
		ascii = strings.ToLower(ascii)
		if _, ok := dns.IsDomainName(ascii + "."); !ok || !strings.Contains(ascii, ".") || strings.ContainsAny(ascii, "* /\\@:\n\r") {
			return nil, errors.New("网关 DNS 后缀范围过大或格式不兼容")
		}
		seen[ascii] = true
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	// A parent route already handles every child; avoid a large repeated list.
	compact := out[:0]
	for _, name := range out {
		covered := false
		for dot := strings.IndexByte(name, '.'); dot >= 0; {
			if seen[name[dot+1:]] {
				covered = true
				break
			}
			next := strings.IndexByte(name[dot+1:], '.')
			if next < 0 {
				break
			}
			dot += next + 1
		}
		if !covered {
			compact = append(compact, name)
		}
	}
	if len(compact) > 128 {
		return nil, errors.New("内网 DNS 后缀过多，当前最多支持 128 个独立后缀")
	}
	return append([]string(nil), compact...), nil
}

type dnsPool struct {
	mu      sync.Mutex
	entries map[string]*dnsEntry
	pending map[string]*dnsPreparation
	closed  bool
	failed  map[string]bool
	prepare func(context.Context, string, CaptureConfig) (aliasBinding, error)
}
type dnsPreparation struct {
	cancel context.CancelFunc
	done   chan struct{}
	err    error // published by closing done
}

type dnsEntry struct {
	once    sync.Once
	server  *splitdns.Server
	cancel  context.CancelFunc
	refs    int
	domains []string
	alias   aliasBinding
	active  func() bool
}
type dnsBinding struct {
	address string
	domains []string
	release func()
	done    <-chan struct{}
	alias   aliasBinding
}

type aliasBinding interface {
	Close() error
	Done() <-chan struct{}
	Exchange(context.Context, []byte) ([]byte, error)
}
type dnsContextKey struct{}
type captureConfigKey struct{}

func (p *dnsPool) acquire(config CaptureConfig) (*dnsBinding, error) {
	return p.acquireContext(context.Background(), config)
}

// Preparation belongs to a single launch and can be cancelled. A committed
// listener belongs to the VPN generation, not to the first launch's context.
// Slow helper/UAC operations never hold the pool mutex.
func (p *dnsPool) acquireContext(ctx context.Context, config CaptureConfig) (*dnsBinding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(config.Domains) == 0 {
		return nil, nil
	}
	if config.Key == "" || (config.Exchange == nil && config.MappedDNS == nil) {
		return nil, errors.New("VPN 核心尚不支持软件 DNS")
	}
	for {
		p.mu.Lock()
		if err := ctx.Err(); err != nil {
			p.mu.Unlock()
			return nil, err
		}
		if p.closed {
			p.mu.Unlock()
			return nil, net.ErrClosed
		}
		if config.Active != nil && !config.Active() {
			p.mu.Unlock()
			return nil, errors.New("VPN 会话已结束")
		}
		if p.failed[config.Key] {
			p.mu.Unlock()
			return nil, errors.New("本次连接的 DNS 助手会话已结束，请重新连接 VPN 后再启动软件")
		}
		if entry := p.entries[config.Key]; entry != nil {
			if strings.Join(entry.domains, "\n") != strings.Join(config.Domains, "\n") {
				p.mu.Unlock()
				return nil, errors.New("VPN DNS 配置发生变化，请重新连接")
			}
			select {
			case <-entry.server.Done():
				p.mu.Unlock()
				return nil, errors.New("软件 DNS 入口已关闭，请重新启动项目")
			default:
			}
			binding := p.bind(config.Key, entry)
			p.mu.Unlock()
			return binding, nil
		}
		if pending := p.pending[config.Key]; pending != nil {
			p.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-pending.done:
				if pending.err != nil && !errors.Is(pending.err, context.Canceled) && !errors.Is(pending.err, context.DeadlineExceeded) {
					return nil, pending.err
				}
			}
			continue
		}
		setup, cancel := context.WithCancel(ctx)
		pending := &dnsPreparation{cancel: cancel, done: make(chan struct{})}
		if p.pending == nil {
			p.pending = make(map[string]*dnsPreparation)
		}
		p.pending[config.Key] = pending
		prepare := p.prepare
		if prepare == nil {
			prepare = prepareMappedDNS
		}
		p.mu.Unlock()

		entry, err := prepareDNSEntry(setup, config, prepare)
		p.mu.Lock()
		if setup.Err() != nil {
			err = setup.Err()
		} else if p.closed {
			err = net.ErrClosed
		} else if config.Active != nil && !config.Active() {
			err = errors.New("VPN 会话已结束")
		}
		if err != nil {
			// Keep the reservation until rollback completes, so a waiting
			// launch cannot install competing rules while cleanup runs.
			p.mu.Unlock()
			if entry != nil {
				entry.close()
			}
			p.mu.Lock()
		} else {
			if p.entries == nil {
				p.entries = make(map[string]*dnsEntry)
			}
			p.entries[config.Key] = entry
		}
		var binding *dnsBinding
		if err == nil {
			binding = p.bind(config.Key, entry)
		}
		pending.err = err
		delete(p.pending, config.Key)
		close(pending.done)
		p.mu.Unlock()
		cancel()
		if err != nil {
			return nil, err
		}
		if entry.alias != nil || entry.active != nil {
			go p.watch(config.Key, entry)
		}
		return binding, nil
	}
}

func prepareDNSEntry(setup context.Context, config CaptureConfig, prepare func(context.Context, string, CaptureConfig) (aliasBinding, error)) (*dnsEntry, error) {
	life, cancel := context.WithCancel(context.Background())
	entry := &dnsEntry{cancel: cancel, domains: append([]string(nil), config.Domains...), active: config.Active}
	ready := make(chan struct{})
	exchange := config.Exchange
	if config.MappedDNS != nil {
		exchange = func(ctx context.Context, packet []byte) ([]byte, error) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-ready:
			}
			if entry.alias == nil {
				return nil, errors.New("软件 DNS 规则尚未就绪")
			}
			return entry.alias.Exchange(ctx, packet)
		}
	}
	server, err := splitdns.Listen(life, exchange)
	if err != nil {
		cancel()
		return nil, err
	}
	entry.server = server
	if config.MappedDNS != nil {
		entry.alias, err = prepare(setup, server.Addr(), config)
		if err == nil && entry.alias == nil {
			err = errors.New("软件 DNS 助手未就绪")
		}
	}
	close(ready)
	return entry, err
}

// bind is called with p.mu held; the returned release may run concurrently
// with a helper failure, pool close, or a different application's release.
func (p *dnsPool) bind(key string, entry *dnsEntry) *dnsBinding {
	entry.refs++
	var once sync.Once
	return &dnsBinding{address: entry.server.Addr(), domains: entry.domains, done: entry.server.Done(), alias: entry.alias, release: func() {
		once.Do(func() {
			p.mu.Lock()
			entry.refs--
			last := entry.refs == 0 && (entry.active == nil || !entry.active())
			if last && p.entries[key] == entry {
				delete(p.entries, key)
			}
			p.mu.Unlock()
			if last {
				entry.close()
			}
		})
	}}
}

func (e *dnsEntry) close() {
	e.once.Do(func() {
		e.cancel()
		_ = e.server.Close()
		if e.alias != nil {
			_ = e.alias.Close()
		}
	})
}

func (p *dnsPool) watch(key string, entry *dnsEntry) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var failed <-chan struct{}
	if entry.alias != nil {
		failed = entry.alias.Done()
	}
	for {
		select {
		case <-entry.server.Done():
		case <-failed:
		case <-ticker.C:
			if entry.active == nil || entry.active() {
				continue
			}
		}
		p.mu.Lock()
		if p.entries[key] == entry {
			if entry.alias != nil && entry.active != nil && entry.active() {
				if p.failed == nil {
					p.failed = map[string]bool{}
				}
				p.failed[key] = true
			}
			delete(p.entries, key)
		}
		p.mu.Unlock()
		entry.close()
		return
	}
}

func (p *dnsPool) close() {
	p.mu.Lock()
	p.closed = true
	entries := p.entries
	p.entries = nil
	pending := make([]*dnsPreparation, 0, len(p.pending))
	for _, preparation := range p.pending {
		preparation.cancel()
		pending = append(pending, preparation)
	}
	p.mu.Unlock()
	for _, entry := range entries {
		entry.close()
	}
	for _, preparation := range pending {
		<-preparation.done
	}
}
