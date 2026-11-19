package localapps

import (
	"context"
	"errors"
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
	failed  map[string]bool
	prepare func(context.Context, string, CaptureConfig) (aliasBinding, error)
}
type dnsEntry struct {
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
	if len(config.Domains) == 0 {
		return nil, nil
	}
	if config.Key == "" || (config.Exchange == nil && config.MappedDNS == nil) {
		return nil, errors.New("VPN 核心尚不支持软件 DNS")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.entries == nil {
		p.entries = make(map[string]*dnsEntry)
	}
	if p.failed[config.Key] {
		return nil, errors.New("本次连接的 DNS 助手会话已结束，请重新连接 VPN 后再启动软件")
	}
	entry := p.entries[config.Key]
	if entry != nil {
		if strings.Join(entry.domains, "\n") != strings.Join(config.Domains, "\n") {
			return nil, errors.New("VPN DNS 配置发生变化，请重新连接")
		}
		select {
		case <-entry.server.Done():
			return nil, errors.New("软件 DNS 入口已关闭，请重新启动项目")
		default:
		}
	} else {
		ctx, cancel := context.WithCancel(context.Background())
		entry = &dnsEntry{cancel: cancel, domains: append([]string(nil), config.Domains...), active: config.Active}
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
		server, err := splitdns.Listen(ctx, exchange)
		if err != nil {
			cancel()
			return nil, err
		}
		entry.server = server
		if config.MappedDNS != nil {
			prepare := p.prepare
			if prepare == nil {
				prepare = prepareMappedDNS
			}
			entry.alias, err = prepare(ctx, server.Addr(), config)
		}
		close(ready)
		if err != nil {
			cancel()
			_ = server.Close()
			return nil, err
		}
		p.entries[config.Key] = entry
		if entry.alias != nil || entry.active != nil {
			go p.watch(config.Key, entry)
		}
	}
	entry.refs++
	var once sync.Once
	return &dnsBinding{address: entry.server.Addr(), domains: entry.domains, done: entry.server.Done(), alias: entry.alias, release: func() {
		once.Do(func() {
			p.mu.Lock()
			entry.refs--
			last := entry.refs == 0 && (entry.active == nil || !entry.active())
			if last {
				if p.entries[config.Key] == entry {
					delete(p.entries, config.Key)
				}
			}
			p.mu.Unlock()
			if last {
				entry.cancel()
				_ = entry.server.Close()
				if entry.alias != nil {
					_ = entry.alias.Close()
				}
			}
		})
	}}, nil
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
		entry.cancel()
		_ = entry.server.Close()
		if entry.alias != nil {
			_ = entry.alias.Close()
		}
		p.mu.Lock()
		if entry.alias != nil && entry.active != nil && entry.active() {
			if p.failed == nil {
				p.failed = map[string]bool{}
			}
			p.failed[key] = true
		}
		if p.entries[key] == entry {
			delete(p.entries, key)
		}
		p.mu.Unlock()
		return
	}
}

func (p *dnsPool) close() {
	p.mu.Lock()
	entries := p.entries
	p.entries = nil
	p.mu.Unlock()
	for _, entry := range entries {
		entry.cancel()
		_ = entry.server.Close()
		if entry.alias != nil {
			_ = entry.alias.Close()
		}
	}
}
