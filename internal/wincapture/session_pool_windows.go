package wincapture

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"sync"

	"github.com/qy/easyconnect/internal/dnsmapping"
)

type pooledSession struct {
	session *Session
	config  Config
	refs    int
}

// There is one authenticated transport and one helper, with independently
// reference-counted gateway generations. The gate also serializes rollback.
type runtimePool struct {
	gate     chan struct{}
	open     func(context.Context, string, Config) (*Session, error)
	runtime  *Session
	sessions map[string]*pooledSession
}

func newSessionPool(open func(context.Context, string, Config) (*Session, error)) *runtimePool {
	return &runtimePool{gate: make(chan struct{}, 1), open: open, sessions: make(map[string]*pooledSession)}
}

func cloneConfig(c Config) Config {
	c.Networks = slices.Clone(c.Networks)
	c.Domains = slices.Clone(c.Domains)
	c.ReservedPools = slices.Clone(c.ReservedPools)
	c.AliasNetworks = slices.Clone(c.AliasNetworks)
	return c
}

func sameSessionConfig(a, b Config) bool {
	// Allocation constraints may grow while an established lease is reused.
	a.ReservedPools, b.ReservedPools = nil, nil
	a.AliasNetworks, b.AliasNetworks = nil, nil
	return reflect.DeepEqual(a, b)
}

func (p *runtimePool) acquire(ctx context.Context, key string, config Config) (*Session, func(), error) {
	if key == "" {
		return nil, nil, errors.New("缺少 VPN 会话身份")
	}
	if err := config.validate(); err != nil {
		return nil, nil, err
	}
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case p.gate <- struct{}{}:
	}
	defer func() { <-p.gate }()
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if p.runtime != nil {
		select {
		case <-p.runtime.Done():
			return nil, nil, errors.Join(errors.New("Windows 网络助手已结束，请先停止现有接管"), p.runtime.Err())
		default:
		}
	}
	entry := p.sessions[key]
	if entry != nil {
		if !sameSessionConfig(entry.config, config) {
			return nil, nil, errors.New("软件接管资源已改变，请重新连接 VPN")
		}
		select {
		case <-entry.session.Done():
			return nil, nil, errors.New("VPN 接管会话已结束")
		default:
		}
	} else {
		id, err := randomID()
		if err != nil {
			return nil, nil, err
		}
		var prefix string
		if p.runtime == nil {
			p.runtime, err = p.open(ctx, id, config)
			if err != nil {
				return nil, nil, err
			}
			prefix = p.runtime.Prefix()
		} else {
			var reply frame
			reply, err = p.runtime.request(ctx, frame{Type: "register", Session: id, Config: &config})
			if err != nil {
				return nil, nil, err
			}
			prefix = reply.Prefix
		}
		s := logicalSession(p.runtime, id, prefix)
		block, parseErr := netip.ParsePrefix(prefix)
		if parseErr != nil || !dnsmapping.ValidPrefix(block) {
			err = errors.New("网络助手返回了无效的会话映射池")
		}
		for _, other := range p.sessions {
			if otherBlock, parseErr := netip.ParsePrefix(other.session.Prefix()); parseErr == nil && otherBlock.Overlaps(block) {
				err = errors.New("网络助手返回了重叠的会话映射池")
			}
		}
		if err == nil {
			err = ctx.Err()
		}
		if err != nil {
			cleanupErr := s.Close()
			if len(p.sessions) == 0 {
				cleanupErr = errors.Join(cleanupErr, p.runtime.Close())
				p.runtime = nil
			}
			return nil, nil, errors.Join(err, cleanupErr)
		}
		entry = &pooledSession{session: s, config: cloneConfig(config)}
		p.sessions[key] = entry
	}
	entry.refs++
	var once sync.Once
	return entry.session, func() {
		once.Do(func() {
			p.gate <- struct{}{}
			defer func() { <-p.gate }()
			entry.refs--
			if entry.refs != 0 {
				return
			}
			_ = entry.session.Close()
			delete(p.sessions, key)
			if len(p.sessions) == 0 {
				_ = p.runtime.Close()
				p.runtime = nil
			}
		})
	}, nil
}
