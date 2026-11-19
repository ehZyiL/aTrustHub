// Package localapps manages explicit browser proxy sessions, local TCP
// forwards, and the experimental Linux process-capture launcher.
package localapps

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/qy/easyconnect/internal/model"
	"github.com/qy/easyconnect/internal/proxy"
)

type View struct {
	ID, PointID, Mode string
	Running           bool
	PID               int
	LocalAddress      string
	Error             string
	Starting          bool
	Stopping          bool
	DNSDomains        int
	Observed          bool
	Connections       Connections
}

type run struct {
	view        View
	stop        func() error
	cancel      context.CancelFunc
	setupDone   chan struct{}
	stopDone    chan struct{}
	active      func() bool
	connections connectionCounters
}

type DialFunc = func(context.Context, string, string) (net.Conn, error)

type managedCapture interface {
	PID() int
	Done() <-chan struct{}
	Err() error
	Close() error
}

type Manager struct {
	mu           sync.Mutex
	runs         map[string]*run
	closed       bool
	onChange     func()
	onAccess     func(AccessEvent)
	captureStart func(context.Context, model.LocalApp, DialFunc) (managedCapture, error)
	dns          dnsPool
}

func NewManager(onChange func(), observers ...func(AccessEvent)) *Manager {
	m := &Manager{runs: make(map[string]*run), onChange: onChange, captureStart: startCapture}
	if len(observers) > 0 {
		m.onAccess = observers[0]
	}
	return m
}

func (m *Manager) notify() {
	if m.onChange != nil {
		m.onChange()
	}
}

func (m *Manager) View(id string) View {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r := m.runs[id]; r != nil {
		v := r.view
		v.Connections = r.connections.snapshot()
		return v
	}
	return View{ID: id}
}

func (m *Manager) Views() []View {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]View, 0, len(m.runs))
	for _, r := range m.runs {
		v := r.view
		v.Connections = r.connections.snapshot()
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (m *Manager) Start(p model.LocalApp, proxyAddress string, connections ...Connection) error {
	p.Normalize()
	if err := p.Validate(); err != nil {
		return err
	}
	if p.Mode == model.LocalAppCapture {
		return errors.New("软件接管需要绑定当前 VPN 会话")
	}
	var connection Connection
	if len(connections) > 0 {
		connection = connections[0]
	}
	if connection.Active != nil && !connection.Active() {
		return net.ErrClosed
	}
	if connection.Dial == nil {
		if err := validateProxy(proxyAddress); err != nil {
			return err
		}
		d, err := proxy.NewSOCKSDialer(proxyAddress, nil)
		if err != nil {
			return err
		}
		connection.Dial = d.DialContext
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return net.ErrClosed
	}
	if r := m.runs[p.ID]; r != nil && (r.view.Running || r.view.Starting || r.view.Stopping) {
		m.mu.Unlock()
		return errors.New("此项目已经启动")
	}
	r := &run{view: View{ID: p.ID, PointID: p.PointID, Mode: p.Mode, Observed: true}}
	dial := m.trackedDial(p, r, connection.Dial)
	// Keep setup serialized with Stop/Close; only local bind/process creation
	// happens here. No upstream VPN dial is performed until a client connects.
	var done <-chan struct{}
	var err error
	var rollback func()
	if p.Mode == model.LocalAppTCPForward {
		var f *forward
		f, err = startForward(p, dial)
		if err == nil {
			r.active = connection.Active
			r.stop, r.view.LocalAddress = func() error { f.close(); return nil }, f.ln.Addr().String()
			done = f.done
		}
	} else {
		ctx, cancel := context.WithCancel(context.Background())
		s := proxy.New(proxy.Options{Addr: "127.0.0.1:0", Dial: dial, Context: ctx, SOCKSOnly: true})
		err = s.Start()
		if err == nil {
			var b *browserProcess
			b, err = launchBrowser(p, s.Addr().String())
			if err == nil {
				r.stop = func() error { cancel(); return s.Close() }
				r.view.PID = b.pid
				browserDone := make(chan struct{})
				done = browserDone
				go func() { _ = b.cmd.Wait(); close(browserDone) }()
			}
		}
		if err != nil {
			rollback = func() { cancel(); _ = s.Close() }
		}
	}
	if err != nil {
		r.view.Error = err.Error()
	} else {
		r.view.Running = true
	}
	m.runs[p.ID] = r
	m.mu.Unlock()
	if rollback != nil {
		rollback()
	}
	m.notify()
	if done != nil {
		go func() {
			<-done
			if p.Mode == model.LocalAppBrowser && r.stop != nil {
				_ = r.stop()
			}
			m.mu.Lock()
			if m.runs[p.ID] == r {
				r.view.Running = false
				r.view.PID = 0
			}
			m.mu.Unlock()
			m.notify()
		}()
	}
	return err
}

// StartCapture reserves the project synchronously, then installs rules behind
// the launch barrier in the background. UI rendering and VPN cancellation do
// not wait on systemd or privileged helper responses.
func (m *Manager) StartCapture(p model.LocalApp, dial DialFunc, active func() bool, configs ...CaptureConfig) error {
	p.Normalize()
	if err := p.Validate(); err != nil {
		return err
	}
	if p.Mode != model.LocalAppCapture || dial == nil || active == nil {
		return errors.New("无效的软件接管请求")
	}
	if !active() {
		return errors.New("该软件所属的 VPN 会话已结束")
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return net.ErrClosed
	}
	if old := m.runs[p.ID]; old != nil && (old.view.Running || old.view.Starting || old.view.Stopping) {
		m.mu.Unlock()
		return errors.New("此项目已经启动")
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &run{view: View{ID: p.ID, PointID: p.PointID, Mode: p.Mode, Starting: true, Observed: true}, cancel: cancel, setupDone: make(chan struct{}), active: active}
	m.runs[p.ID] = r
	m.mu.Unlock()
	m.notify()
	go func() {
		var binding *dnsBinding
		setupErr := checkCaptureProgram(ctx, p)
		if setupErr == nil && len(configs) > 0 {
			ctx = context.WithValue(ctx, captureConfigKey{}, configs[0])
			binding, setupErr = m.dns.acquire(configs[0])
			if setupErr == nil && binding != nil {
				ctx = context.WithValue(ctx, dnsContextKey{}, binding)
				defer binding.release()
			}
		}
		if setupErr != nil {
			m.mu.Lock()
			r.view.Starting = false
			if ctx.Err() == nil {
				r.view.Error = setupErr.Error()
			}
			m.mu.Unlock()
			cancel()
			close(r.setupDone)
			m.notify()
			return
		}
		process, err := m.captureStart(ctx, p, m.trackedDial(p, r, dial))
		m.mu.Lock()
		if m.closed || ctx.Err() != nil || m.runs[p.ID] != r {
			m.mu.Unlock()
			if process != nil {
				_ = process.Close()
			}
			if binding != nil {
				binding.release()
			}
			close(r.setupDone)
			return
		}
		r.view.Starting = false
		if err != nil {
			r.view.Error = err.Error()
			m.mu.Unlock()
			cancel()
			if binding != nil {
				binding.release()
			}
			close(r.setupDone)
			m.notify()
			return
		}
		r.stop = func() error {
			err := process.Close()
			if binding != nil {
				binding.release()
			}
			return err
		}
		r.view.Running = true
		r.view.PID = process.PID()
		var dnsDone <-chan struct{}
		if binding != nil {
			r.view.DNSDomains = len(binding.domains)
			dnsDone = binding.done
		}
		m.mu.Unlock()
		close(r.setupDone)
		m.notify()
		var runErr error
		select {
		case <-process.Done():
		case <-dnsDone:
			runErr = errors.New("内网 DNS 服务已停止，软件接管已解除，请重新启动项目")
		}
		closeErr := process.Close()
		if closeErr == nil {
			closeErr = process.Err()
		}
		if binding != nil {
			binding.release()
		}
		m.mu.Lock()
		if m.runs[p.ID] == r {
			r.view.Running = false
			r.view.PID = 0
			if !r.view.Stopping {
				if err := errors.Join(runErr, closeErr); err != nil {
					r.view.Error = err.Error()
				}
			}
		}
		m.mu.Unlock()
		cancel()
		m.notify()
	}()
	return nil
}

func (m *Manager) Stop(id string) error {
	return m.stop(id, nil)
}

func (m *Manager) stop(id string, expected *run) error {
	m.mu.Lock()
	r := m.runs[id]
	if r == nil || (expected != nil && r != expected) || (!r.view.Running && !r.view.Starting && !r.view.Stopping) {
		m.mu.Unlock()
		return nil
	}
	if r.view.Stopping {
		done := r.stopDone
		m.mu.Unlock()
		<-done
		return nil
	}
	if r.view.Mode == model.LocalAppBrowser {
		m.mu.Unlock()
		return errors.New("请关闭该项目启动的独立浏览器窗口，再编辑或重新启动")
	}
	// Reserve this project while waiting, without blocking every View/UI read.
	r.view.Stopping = true
	r.stopDone = make(chan struct{})
	if r.cancel != nil {
		r.cancel()
	}
	m.mu.Unlock()
	m.notify()
	if r.setupDone != nil {
		<-r.setupDone
	}
	m.mu.Lock()
	stop := r.stop
	m.mu.Unlock()
	var err error
	if stop != nil {
		err = stop()
	}
	m.mu.Lock()
	r.view.Running = false
	r.view.Starting = false
	r.view.Stopping = false
	r.view.PID = 0
	if err != nil {
		r.view.Error = err.Error()
	}
	close(r.stopDone)
	m.mu.Unlock()
	m.notify()
	return err
}

// StopExpiredCaptures also drains session-bound forwards and catches a reconnect
// between UI refreshes: online does not mean this launch's session is alive.
func (m *Manager) StopExpiredCaptures() {
	m.mu.Lock()
	runs := make(map[string]*run)
	for id, r := range m.runs {
		if r.active != nil && (r.view.Running || r.view.Starting) {
			runs[id] = r
		}
	}
	m.mu.Unlock()
	for id, r := range runs {
		if !r.active() {
			_ = m.stop(id, r)
		}
	}
}

// StopPoint drains forwards and capture leases. A disconnected VPN must not terminate a
// user's browser; its requests fail through the now-unavailable proxy.
func (m *Manager) StopPoint(pointID string) {
	for _, v := range m.Views() {
		if v.PointID == pointID && v.Mode != model.LocalAppBrowser {
			_ = m.Stop(v.ID)
		}
	}
}

func (m *Manager) Close() error {
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()
	var errs []error
	for _, v := range m.Views() {
		if v.Mode != model.LocalAppBrowser {
			errs = append(errs, m.Stop(v.ID))
		} else {
			m.mu.Lock()
			stop := m.runs[v.ID].stop
			m.mu.Unlock()
			if stop != nil {
				errs = append(errs, stop())
			}
		}
	}
	m.dns.close()
	return errors.Join(errs...)
}

type forward struct {
	ln     net.Listener
	dial   DialFunc
	target string
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once
	mu     sync.Mutex
	closed bool
	conns  map[net.Conn]struct{}
	wg     sync.WaitGroup
}

func startForward(p model.LocalApp, dial DialFunc) (*forward, error) {
	ln, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(p.ListenPort)))
	if err != nil {
		return nil, fmt.Errorf("本地端口无法监听：%w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	f := &forward{ln: ln, dial: dial, target: p.RemoteAddress, ctx: ctx, cancel: cancel, done: make(chan struct{}), conns: make(map[net.Conn]struct{})}
	go f.accept()
	return f, nil
}

func (f *forward) accept() {
	defer close(f.done)
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		if !f.track(conn) {
			_ = conn.Close()
			return
		}
		f.wg.Add(1)
		go func() { defer f.wg.Done(); f.handle(conn) }()
	}
}

func (f *forward) track(conn net.Conn) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return false
	}
	f.conns[conn] = struct{}{}
	return true
}

func (f *forward) release(conn net.Conn) {
	_ = conn.Close()
	f.mu.Lock()
	delete(f.conns, conn)
	f.mu.Unlock()
}

func (f *forward) handle(conn net.Conn) {
	defer f.release(conn)
	ctx, cancel := context.WithTimeout(f.ctx, 15*time.Second)
	upstream, err := f.dial(ctx, "tcp", f.target)
	cancel()
	if err != nil {
		return
	}
	if !f.track(upstream) {
		_ = upstream.Close()
		return
	}
	defer f.release(upstream)
	proxy.Relay(conn, upstream)
}

func (f *forward) close() {
	f.once.Do(func() {
		f.cancel()
		f.mu.Lock()
		f.closed = true
		conns := make([]net.Conn, 0, len(f.conns))
		for conn := range f.conns {
			conns = append(conns, conn)
		}
		f.mu.Unlock()
		_ = f.ln.Close()
		for _, conn := range conns {
			_ = conn.Close()
		}
		<-f.done
		f.wg.Wait()
	})
}
