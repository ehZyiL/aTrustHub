package wincapture

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/qy/easyconnect/internal/proxy"
	proxy2 "golang.org/x/net/proxy"
)

var sessionPool = newSessionPool(openSession)

func Acquire(ctx context.Context, key string, config Config) (*Session, func(), error) {
	return sessionPool.acquire(ctx, key, config)
}

func openSession(ctx context.Context, id string, config Config) (*Session, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	f, err := startHelper(ctx)
	if err != nil {
		return nil, fmt.Errorf("连接 Windows 网络助手：%w", err)
	}
	s := newSession(f)
	reply, err := s.request(ctx, frame{Type: "configure", Session: id, Config: &config})
	if err != nil {
		err = fmt.Errorf("初始化 Windows 接管网络：%w", err)
		s.fail(err)
		return nil, err
	}
	s.prefix = reply.Prefix
	if reply.Upstream == nil || reply.Upstream.validate() != nil {
		err := errors.New("网络助手没有提供可信原出口")
		s.fail(err)
		return nil, err
	}
	s.original, err = proxy.NewSOCKSDialer(reply.Upstream.Address, &proxy2.Auth{User: reply.Upstream.Username, Password: reply.Upstream.Password})
	if err != nil {
		s.fail(err)
		return nil, err
	}
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
