package wincapture

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"
)

// A single helper multiplexes applications in one VPN generation. Overlapping
// resource policies from concurrent VPNs cannot silently steal each other's
// routes. Explicit proxies remain available for the other connections.
var sessionPool struct {
	gate    chan struct{}
	key     string
	config  Config
	session *Session
	refs    int
}

func init() { sessionPool.gate = make(chan struct{}, 1) }

func Acquire(ctx context.Context, key string, config Config) (*Session, func(), error) {
	if key == "" {
		return nil, nil, errors.New("缺少 VPN 会话身份")
	}
	if err := config.validate(); err != nil {
		return nil, nil, err
	}
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case sessionPool.gate <- struct{}{}:
	}
	defer func() { <-sessionPool.gate }()
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if sessionPool.session != nil {
		if sessionPool.key != key {
			return nil, nil, errors.New("Windows 首版一次只支持一个 VPN 会话的软件接管，请先停止其他会话的接管")
		}
		if !sameSessionConfig(config, sessionPool.config) {
			return nil, nil, errors.New("软件接管资源已改变，请重新连接 VPN")
		}
		select {
		case <-sessionPool.session.Done():
			return nil, nil, errors.New("Windows 网络助手已结束，请重新连接 VPN")
		default:
		}
	} else {
		s, err := openSession(ctx, config)
		if err != nil {
			return nil, nil, err
		}
		sessionPool.session, sessionPool.key, sessionPool.config = s, key, config
	}
	s := sessionPool.session
	sessionPool.refs++
	var once sync.Once
	return s, func() {
		once.Do(func() {
			sessionPool.gate <- struct{}{}
			defer func() { <-sessionPool.gate }()
			sessionPool.refs--
			if sessionPool.refs == 0 {
				_ = s.Close()
				sessionPool.session, sessionPool.key, sessionPool.config = nil, "", Config{}
			}
		})
	}, nil
}

func sameSessionConfig(a, b Config) bool {
	// These only constrain initial allocation; refreshing them must not stop
	// another application using the already committed session/prefix.
	a.ReservedPools, b.ReservedPools = nil, nil
	a.AliasNetworks, b.AliasNetworks = nil, nil
	return reflect.DeepEqual(a, b)
}

func openSession(ctx context.Context, config Config) (*Session, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	f, err := startHelper(ctx)
	if err != nil {
		return nil, fmt.Errorf("连接 Windows 网络助手：%w", err)
	}
	s := newSession(f)
	reply, err := s.request(ctx, frame{Type: "configure", Config: &config})
	if err != nil {
		err = fmt.Errorf("初始化 Windows 接管网络：%w", err)
		s.fail(err)
		return nil, err
	}
	s.prefix = reply.Prefix
	go func() {
		tick := time.NewTicker(3 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-s.done:
				return
			case <-tick.C:
				if _, err := s.request(context.Background(), frame{Type: "ping"}); err != nil {
					s.fail(err)
					return
				}
			}
		}
	}()
	return s, nil
}

func (s *Session) Attach(ctx context.Context, p *Process, upstream Upstream) (func() error, error) {
	if err := upstream.validate(); err != nil {
		return nil, err
	}
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	_, err = s.request(ctx, frame{Type: "attach", Attach: &attach{ID: id, Job: p.JobHandle(), Upstream: upstream}})
	if err != nil {
		return nil, fmt.Errorf("登记软件接管：%w", err)
	}
	var once sync.Once
	var closeErr error
	return func() error {
		once.Do(func() { _, closeErr = s.request(context.Background(), frame{Type: "detach", ID: id}) })
		return closeErr
	}, nil
}
