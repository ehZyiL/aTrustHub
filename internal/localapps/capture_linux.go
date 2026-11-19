package localapps

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"

	"github.com/qy/easyconnect/internal/capture"
	"github.com/qy/easyconnect/internal/model"
	"github.com/qy/easyconnect/internal/proxy"
	"github.com/qy/easyconnect/internal/resolved"
)

type captureProcess struct {
	process *capture.Process
	proxy   *proxy.Server
	cancel  context.CancelFunc
	once    sync.Once
	err     error
}

func (c *captureProcess) PID() int              { return c.process.PID }
func (c *captureProcess) Done() <-chan struct{} { return c.process.Done() }
func (c *captureProcess) Err() error            { return c.process.Err() }
func (c *captureProcess) Close() error {
	c.once.Do(func() { c.err = c.process.Close(); c.cancel(); _ = c.proxy.Close() })
	return c.err
}

func startCapture(ctx context.Context, p model.LocalApp, dial DialFunc) (managedCapture, error) {
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
	upstream := capture.Upstream{Address: s.Addr().String(), Username: "capture", Password: password}
	if config, ok := ctx.Value(captureConfigKey{}).(CaptureConfig); ok {
		upstream.Networks = config.Networks
	}
	if binding, ok := ctx.Value(dnsContextKey{}).(*dnsBinding); ok {
		upstream.DNS = &resolved.Config{Address: binding.address, Domains: binding.domains}
		if mapped, ok := binding.alias.(*mappedDNS); ok {
			upstream.Alias = mapped.lease.Ref()
		}
	}
	process, err := capture.Launch(ctx, capture.Program{Executable: p.Executable, Args: p.Args, WorkDir: p.WorkDir}, upstream)
	if err != nil {
		cancel()
		_ = s.Close()
		return nil, err
	}
	return &captureProcess{process: process, proxy: s, cancel: cancel}, nil
}
