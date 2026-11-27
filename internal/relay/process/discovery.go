package process

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ehzyil/connect-hub/internal/relay/discovery"
	discoverycontract "github.com/ehzyil/connect-hub/internal/relay/discovery/contract"
)

// DiscoveryRuntime shares one short-lived relay process between announcement
// and browsing work. Constructing it opens no sockets and starts no process.
type DiscoveryRuntime struct {
	mu           sync.Mutex
	writeMu      sync.Mutex
	executable   string
	verified     bool
	logf         func(string, ...any)
	onChange     func(discoverycontract.Status)
	emit         func(discoverycontract.Snapshot)
	cmd          *exec.Cmd
	stdin        io.WriteCloser
	ready        chan struct{}
	readyErr     error
	procDone     chan struct{}
	procErr      error
	retiring     bool
	acks         map[uint64]chan event
	status       discoverycontract.Status
	snapshot     discoverycontract.Snapshot
	browseErr    string
	browseLive   bool
	pubClosed    bool
	browseClosed bool
	seq          atomic.Uint64
}

func NewDiscoveryRuntime(executable string, logf func(string, ...any), onChange func(discoverycontract.Status), emit func(discoverycontract.Snapshot)) *DiscoveryRuntime {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &DiscoveryRuntime{executable: executable, logf: logf, onChange: onChange, emit: emit,
		acks: make(map[uint64]chan event), status: discoverycontract.Status{State: discoverycontract.StatusIdle}}
}

type DiscoveryPublisher struct {
	runtime *DiscoveryRuntime
}

type DiscoveryBrowser struct {
	runtime *DiscoveryRuntime
}

func (r *DiscoveryRuntime) Publisher() *DiscoveryPublisher { return &DiscoveryPublisher{runtime: r} }
func (r *DiscoveryRuntime) Browser() *DiscoveryBrowser     { return &DiscoveryBrowser{runtime: r} }

func (p *DiscoveryPublisher) Set(a discoverycontract.Announcement) {
	if err := p.runtime.send(command{Operation: "publish-set", Announcement: &a}, false); err != nil {
		p.runtime.setStatus(discoverycontract.Status{State: discoverycontract.StatusFailed, Message: err.Error(), Generation: a.Generation})
	}
}

func (p *DiscoveryPublisher) Clear() {
	_ = p.runtime.sendIfRunning(command{Operation: "publish-clear"}, false)
}

func (p *DiscoveryPublisher) Status() discoverycontract.Status {
	p.runtime.mu.Lock()
	defer p.runtime.mu.Unlock()
	return p.runtime.status
}

func (p *DiscoveryPublisher) Close(ctx context.Context) error {
	_ = p.runtime.sendIfRunning(command{Operation: "publish-clear"}, false)
	p.runtime.mu.Lock()
	p.runtime.pubClosed = true
	closeNow := p.runtime.browseClosed
	p.runtime.mu.Unlock()
	if closeNow {
		return p.runtime.shutdown(ctx)
	}
	return nil
}

func (b *DiscoveryBrowser) Start(ifaces []discoverycontract.Interface) error {
	b.runtime.mu.Lock()
	if b.runtime.browseClosed {
		b.runtime.mu.Unlock()
		return errors.New("发现浏览器已退出")
	}
	b.runtime.browseLive = true
	b.runtime.mu.Unlock()
	err := b.runtime.send(command{Operation: "browse-start", Interfaces: append([]discoverycontract.Interface(nil), ifaces...)}, true)
	if err != nil {
		b.runtime.mu.Lock()
		b.runtime.browseLive = false
		b.runtime.browseErr = err.Error()
		b.runtime.mu.Unlock()
	}
	return err
}

func (b *DiscoveryBrowser) Refresh() error {
	return b.runtime.sendIfRunning(command{Operation: "browse-refresh"}, true)
}

func (b *DiscoveryBrowser) Snapshot() discoverycontract.Snapshot {
	b.runtime.mu.Lock()
	defer b.runtime.mu.Unlock()
	s := b.runtime.snapshot
	s.Candidates = append([]discoverycontract.Candidate(nil), s.Candidates...)
	return s
}

func (b *DiscoveryBrowser) Err() string {
	b.runtime.mu.Lock()
	defer b.runtime.mu.Unlock()
	return b.runtime.browseErr
}

func (b *DiscoveryBrowser) Close() error {
	b.runtime.mu.Lock()
	b.runtime.browseLive = false
	b.runtime.mu.Unlock()
	return b.runtime.sendIfRunning(command{Operation: "browse-close"}, true)
}

func (b *DiscoveryBrowser) Shutdown() error {
	b.runtime.mu.Lock()
	b.runtime.browseLive = false
	b.runtime.browseClosed = true
	closeNow := b.runtime.pubClosed
	b.runtime.mu.Unlock()
	if closeNow {
		return b.runtime.shutdown(context.Background())
	}
	return b.runtime.sendIfRunning(command{Operation: "browse-close"}, true)
}

func (r *DiscoveryRuntime) setStatus(status discoverycontract.Status) {
	r.mu.Lock()
	r.status = status
	callback := r.onChange
	r.mu.Unlock()
	if callback != nil {
		callback(status)
	}
}

func (r *DiscoveryRuntime) ensure() error {
	for {
		r.mu.Lock()
		if r.cmd != nil {
			if r.retiring {
				previousDone := r.procDone
				r.mu.Unlock()
				if previousDone == nil {
					continue
				}
				select {
				case <-previousDone:
					continue
				case <-time.After(5 * time.Second):
					return errors.New("发现组件退出超时")
				}
			}
			ready := r.ready
			r.mu.Unlock()
			if ready == nil {
				return nil
			}
			select {
			case <-ready:
				r.mu.Lock()
				err := r.readyErr
				r.mu.Unlock()
				return err
			case <-time.After(8 * time.Second):
				return errors.New("发现组件启动超时")
			}
		}
		if r.procDone != nil {
			previousDone := r.procDone
			select {
			case <-previousDone:
			default:
				r.mu.Unlock()
				select {
				case <-previousDone:
					continue
				case <-time.After(5 * time.Second):
					return errors.New("发现组件退出超时")
				}
			}
		}
		if r.executable == "" {
			r.mu.Unlock()
			return errors.New("缺少局域网发现组件 connect-hub-relay")
		}
		if !r.verified {
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			probe := exec.CommandContext(ctx, r.executable, "--protocol-version")
			out, err := probe.Output()
			cancel()
			if err != nil || strings.TrimSpace(string(out)) != ProtocolVersion {
				r.mu.Unlock()
				return errors.New("局域网发现组件版本不兼容，请重新安装完整程序")
			}
			r.verified = true
		}
		cmd := exec.Command(r.executable)
		stdin, err := cmd.StdinPipe()
		if err != nil {
			r.mu.Unlock()
			return err
		}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			_ = stdin.Close()
			r.mu.Unlock()
			return err
		}
		cmd.Stderr = io.Discard
		if err := cmd.Start(); err != nil {
			_ = stdin.Close()
			r.mu.Unlock()
			return fmt.Errorf("局域网发现组件无法启动：%w", err)
		}
		if err := json.NewEncoder(stdin).Encode(startup{Version: ProtocolVersion, Mode: "discovery"}); err != nil {
			_ = cmd.Process.Kill()
			_ = stdin.Close()
			r.mu.Unlock()
			return err
		}
		r.cmd, r.stdin, r.ready, r.readyErr, r.retiring = cmd, stdin, make(chan struct{}), nil, false
		r.procDone, r.procErr = make(chan struct{}), nil
		ready := r.ready
		procDone := r.procDone
		r.mu.Unlock()
		go r.readEvents(stdout, ready)
		go func() {
			waitErr := cmd.Wait()
			r.mu.Lock()
			if r.cmd == cmd {
				r.cmd, r.stdin = nil, nil
				r.procErr = waitErr
				r.retiring = false
				if r.ready != nil {
					select {
					case <-r.ready:
					default:
						r.readyErr = waitErr
						close(r.ready)
					}
				}
				if waitErr != nil && !r.browseClosed {
					r.browseErr = fmt.Sprintf("发现组件退出异常：%v", waitErr)
				}
			}
			r.mu.Unlock()
			close(procDone)
		}()
		select {
		case <-ready:
			r.mu.Lock()
			err = r.readyErr
			r.mu.Unlock()
			return err
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			return errors.New("发现组件握手超时")
		}
	}
}

func (r *DiscoveryRuntime) readEvents(reader io.Reader, ready chan struct{}) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 256<<10)
	for scanner.Scan() {
		var e event
		if json.Unmarshal(scanner.Bytes(), &e) != nil {
			continue
		}
		if e.Kind == "ready" {
			r.mu.Lock()
			r.readyErr = nil
			select {
			case <-ready:
			default:
				close(ready)
			}
			r.mu.Unlock()
			continue
		}
		r.mu.Lock()
		if e.ID != 0 {
			if ack := r.acks[e.ID]; ack != nil {
				select {
				case ack <- e:
				default:
				}
			}
		}
		statusCallback, snapshotCallback := r.onChange, r.emit
		if e.Status != nil {
			r.status = *e.Status
		}
		if e.Snapshot != nil {
			r.snapshot = *e.Snapshot
			r.snapshot.Candidates = append([]discoverycontract.Candidate(nil), e.Snapshot.Candidates...)
			r.browseErr = ""
		}
		if e.Kind == "browse-error" {
			r.browseErr = e.Error
		}
		if e.Kind == "idle" {
			r.browseLive = false
			r.retiring = true
		}
		r.mu.Unlock()
		if e.Kind == "log" && e.Error != "" {
			r.logf("%s", e.Error)
		}
		if e.Status != nil && statusCallback != nil {
			statusCallback(*e.Status)
		}
		if e.Snapshot != nil && snapshotCallback != nil {
			snapshotCallback(*e.Snapshot)
		}
	}
}

func (r *DiscoveryRuntime) send(c command, waitAck bool) error {
	if err := r.ensure(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	r.mu.Lock()
	ready := r.ready
	r.mu.Unlock()
	return r.sendExisting(ctx, c, ready, waitAck)
}

func (r *DiscoveryRuntime) sendIfRunning(c command, waitAck bool) error {
	r.mu.Lock()
	running := r.cmd != nil && !r.retiring
	r.mu.Unlock()
	if !running {
		return nil
	}
	return r.send(c, waitAck)
}

func (r *DiscoveryRuntime) sendExisting(ctx context.Context, c command, ready chan struct{}, waitAck ...bool) error {
	if ready != nil {
		select {
		case <-ready:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	var ack chan event
	if len(waitAck) != 0 && waitAck[0] {
		c.ID = r.seq.Add(1)
		ack = make(chan event, 1)
		r.mu.Lock()
		r.acks[c.ID] = ack
		r.mu.Unlock()
		defer func() { r.mu.Lock(); delete(r.acks, c.ID); r.mu.Unlock() }()
	}
	r.writeMu.Lock()
	r.mu.Lock()
	stdin := r.stdin
	r.mu.Unlock()
	if stdin == nil {
		r.writeMu.Unlock()
		return errors.New("发现组件已退出")
	}
	err := json.NewEncoder(stdin).Encode(c)
	r.writeMu.Unlock()
	if err != nil {
		return err
	}
	if ack == nil {
		return nil
	}
	select {
	case result := <-ack:
		if result.Error != "" {
			return errors.New(result.Error)
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *DiscoveryRuntime) shutdown(ctx context.Context) error {
	r.mu.Lock()
	running := r.cmd != nil && !r.retiring
	retiring := r.retiring
	done := r.procDone
	r.mu.Unlock()
	if !running {
		if retiring && done != nil {
			select {
			case <-done:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	}
	err := r.send(command{Operation: "shutdown"}, true)
	if done == nil {
		return err
	}
	select {
	case <-done:
		r.mu.Lock()
		waitErr := r.procErr
		r.mu.Unlock()
		if err == nil && waitErr != nil {
			err = waitErr
		}
	case <-ctx.Done():
		r.mu.Lock()
		cmd := r.cmd
		r.mu.Unlock()
		if cmd != nil && cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return errors.Join(err, ctx.Err())
	}
	return err
}

func runDiscoveryChild(scanner *bufio.Scanner, out io.Writer) error {
	var writeMu sync.Mutex
	write := func(e event) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return json.NewEncoder(out).Encode(e)
	}
	logf := func(format string, args ...any) { _ = write(event{Kind: "log", Error: fmt.Sprintf(format, args...)}) }
	backend := discovery.NewMDNSBackend(logf)
	pub := discovery.NewPublisher(discovery.PublisherOptions{Backend: backend, Logf: logf,
		OnChange: func(status discoverycontract.Status) { _ = write(event{Kind: "status", Status: &status}) }})
	browser := discovery.NewBrowser(discovery.BrowserOptions{Backend: backend, Logf: logf,
		Emit: func(snapshot discoverycontract.Snapshot) {
			_ = write(event{Kind: "browse-snapshot", Snapshot: &snapshot})
		}})
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = pub.Close(ctx)
		_ = browser.Shutdown()
	}()
	if err := write(event{Kind: "ready"}); err != nil {
		return err
	}
	type queued struct {
		command command
		err     error
	}
	commands := make(chan queued, 8)
	go func() {
		for scanner.Scan() {
			var c command
			err := json.Unmarshal(scanner.Bytes(), &c)
			commands <- queued{command: c, err: err}
		}
		commands <- queued{command: command{Operation: "shutdown"}}
	}()
	var browserLive bool
	var idleSince time.Time
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	ack := func(id uint64, err error) error {
		e := event{Kind: "ack", ID: id}
		if err != nil {
			e.Error = err.Error()
		}
		return write(e)
	}
	for {
		select {
		case item := <-commands:
			c := item.command
			if item.err != nil {
				if err := ack(c.ID, item.err); err != nil {
					return err
				}
				continue
			}
			var err error
			switch c.Operation {
			case "publish-set":
				if c.Announcement == nil {
					err = errors.New("缺少发布内容")
				} else {
					pub.Set(*c.Announcement)
				}
			case "publish-clear":
				pub.Clear()
			case "browse-start":
				err = browser.Start(c.Interfaces)
				browserLive = err == nil
				if err != nil {
					_ = write(event{Kind: "browse-error", Error: err.Error()})
				}
			case "browse-refresh":
				err = browser.Refresh()
				if err != nil {
					_ = write(event{Kind: "browse-error", Error: err.Error()})
				}
			case "browse-close":
				err = browser.Close()
				browserLive = false
			case "shutdown":
				if err := ack(c.ID, nil); err != nil {
					return err
				}
				return nil
			default:
				err = fmt.Errorf("未知 discovery 操作：%s", c.Operation)
			}
			if err := ack(c.ID, err); err != nil {
				return err
			}
		case <-ticker.C:
			if !browserLive && pub.Status().State == discoverycontract.StatusIdle {
				if idleSince.IsZero() {
					idleSince = time.Now()
				} else if time.Since(idleSince) >= time.Second && len(commands) == 0 {
					_ = write(event{Kind: "idle"})
					return nil
				}
			} else {
				idleSince = time.Time{}
			}
		}
	}
}
