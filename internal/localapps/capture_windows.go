package localapps

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"

	"github.com/qy/easyconnect/internal/model"
	"github.com/qy/easyconnect/internal/proxy"
	"github.com/qy/easyconnect/internal/wincapture"
)

type captureProcess struct {
	process *wincapture.Process
	proxy   *proxy.Server
	cancel  context.CancelFunc
	detach  func() error
	release func()
	done    chan struct{}
	once    sync.Once
	mu      sync.Mutex
	err     error
}

func (c *captureProcess) PID() int              { return c.process.PID() }
func (c *captureProcess) Done() <-chan struct{} { return c.done }
func (c *captureProcess) Err() error            { c.mu.Lock(); defer c.mu.Unlock(); return c.err }
func (c *captureProcess) Close() error {
	c.once.Do(func() {
		err := c.detach()
		c.cancel()
		err = errors.Join(err, c.proxy.Close(), c.process.Close())
		c.release()
		c.mu.Lock()
		c.err = errors.Join(c.err, err)
		c.mu.Unlock()
		close(c.done)
	})
	return c.Err()
}

func windowsConfig(ctx context.Context, config CaptureConfig) wincapture.Config {
	result := wincapture.Config{Networks: config.Networks, Gateway: config.Gateway}
	if binding, ok := ctx.Value(dnsContextKey{}).(*dnsBinding); ok {
		result.DNSAddress, result.Domains = binding.address, binding.domains
	}
	return result
}

func startCapture(ctx context.Context, p model.LocalApp, dial DialFunc) (managedCapture, error) {
	config, ok := ctx.Value(captureConfigKey{}).(CaptureConfig)
	if !ok {
		return nil, errors.New("Windows 软件接管需要当前 VPN 资源信息")
	}
	session, release, err := wincapture.Acquire(ctx, config.Key, windowsConfig(ctx, config))
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			release()
		}
	}()
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return nil, err
	}
	password := hex.EncodeToString(secret[:])
	life, cancel := context.WithCancel(context.Background())
	s := proxy.New(proxy.Options{Addr: "127.0.0.1:0", Auth: &proxy.Auth{Username: "capture", Credential: password}, Dial: dial, Context: life, SOCKSOnly: true})
	if err := s.Start(); err != nil {
		cancel()
		return nil, err
	}
	defer func() {
		if !keep {
			cancel()
			_ = s.Close()
		}
	}()
	process, err := wincapture.Prepare(ctx, wincapture.Program{Executable: p.Executable, Args: p.Args, WorkDir: p.WorkDir})
	if err != nil {
		return nil, err
	}
	defer func() {
		if !keep {
			_ = process.Close()
		}
	}()
	detach, err := session.Attach(ctx, process, wincapture.Upstream{Address: s.Addr().String(), Username: "capture", Password: password})
	if err != nil {
		return nil, err
	}
	defer func() {
		if !keep {
			_ = detach()
		}
	}()
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if config.Active != nil && !config.Active() {
		return nil, errors.New("VPN 会话已结束")
	}
	select {
	case <-session.Done():
		return nil, errors.New("Windows 网络助手已停止，取消启动软件")
	default:
	}
	if err = process.Launch(); err != nil {
		return nil, err
	}
	c := &captureProcess{process: process, proxy: s, cancel: cancel, detach: detach, release: release, done: make(chan struct{})}
	keep = true
	go func() {
		select {
		case <-ctx.Done():
		case <-process.Done():
		case <-session.Done():
			c.mu.Lock()
			c.err = session.Err()
			if c.err == nil {
				c.err = errors.New("Windows 网络助手已停止，请重启接管项目")
			}
			c.mu.Unlock()
		}
		_ = c.Close()
	}()
	return c, nil
}
