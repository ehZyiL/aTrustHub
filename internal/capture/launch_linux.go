package capture

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Program struct {
	Executable string   `json:"executable"`
	Args       []string `json:"args,omitempty"`
	WorkDir    string   `json:"workDir,omitempty"`
}

func (p Program) validate() error {
	if !filepath.IsAbs(p.Executable) || strings.ContainsRune(p.Executable, 0) {
		return errors.New("capture: executable must be an absolute path")
	}
	if p.WorkDir != "" && (!filepath.IsAbs(p.WorkDir) || strings.ContainsRune(p.WorkDir, 0)) {
		return errors.New("capture: invalid working directory")
	}
	if len(p.Args) > 256 {
		return errors.New("capture: too many launch arguments")
	}
	for _, arg := range p.Args {
		if len(arg) > 8192 || strings.ContainsRune(arg, 0) {
			return errors.New("capture: invalid launch argument")
		}
	}
	return nil
}

type launchMessage struct {
	Program   *Program `json:"program,omitempty"`
	Release   bool     `json:"release,omitempty"`
	PID       int      `json:"pid,omitempty"`
	StartTime uint64   `json:"startTime,omitempty"`
	Error     string   `json:"error,omitempty"`
}

// RunLaunchBarrier executes only in the normal user's new systemd scope.
// No target code runs until the GUI acknowledges successful rule installation.
// EOF before release exits without starting the program. After Start, losing
// the GUI does not kill the user's program.
func RunLaunchBarrier(input io.Reader, output io.Writer) error {
	if os.Geteuid() == 0 {
		return errors.New("capture: target software must not run as root")
	}
	r := bufio.NewReaderSize(input, maxFrame)
	var msg launchMessage
	if err := readFrame(r, &msg); err != nil {
		return err
	}
	if msg.Program == nil {
		return errors.New("capture: missing launch request")
	}
	p := *msg.Program
	report := func(err error) error { _ = writeFrame(output, launchMessage{Error: err.Error()}); return err }
	if err := p.validate(); err != nil {
		return report(err)
	}
	identity, err := identifyProcess(os.Getpid())
	if err != nil {
		return report(err)
	}
	if err := writeFrame(output, launchMessage{PID: os.Getpid(), StartTime: identity.StartTime}); err != nil {
		return err
	}
	var commit launchMessage
	if err := readFrame(r, &commit); err != nil {
		return err
	}
	if !commit.Release {
		return errors.New("capture: launch cancelled")
	}
	cmd := exec.Command(p.Executable, p.Args...)
	cmd.Dir = p.WorkDir
	if err := cmd.Start(); err != nil {
		return report(fmt.Errorf("启动软件失败：%w", err))
	}
	// os/exec's nil stdio is /dev/null. Target output never becomes control
	// traffic, and inherited pipe closure cannot terminate the application.
	_ = writeFrame(output, launchMessage{PID: cmd.Process.Pid})
	return cmd.Wait()
}

// Process owns capture, not the user's program. Close restores system routing
// for future connections and leaves the application and its children running.
type Process struct {
	PID    int
	id     string
	client *controlClient
	done   chan struct{}
	once   sync.Once
	mu     sync.Mutex
	err    error
}

func (p *Process) Done() <-chan struct{} { return p.done }
func (p *Process) Err() error            { p.mu.Lock(); defer p.mu.Unlock(); return p.err }

func (p *Process) finish(err error) {
	p.once.Do(func() {
		p.client.conn.Close()
		p.mu.Lock()
		p.err = err
		p.mu.Unlock()
		close(p.done)
	})
}

func (p *Process) Close() error {
	select {
	case <-p.done:
		return p.Err()
	default:
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := p.client.call(ctx, frame{Type: "detach", ID: p.id})
	p.finish(err)
	return err
}

func (p *Process) heartbeat() {
	ticker := time.NewTicker(8 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-p.done:
			return
		case <-ticker.C:
		}
		res, err := p.client.call(context.Background(), frame{Type: "ping", ID: p.id})
		if err != nil || !res.Active {
			p.finish(err)
			return
		}
	}
}

// Launch requires an already running root helper and a private authenticated
// SOCKS listener bound to one VPN session. It never invokes a shell or pkexec.
func Launch(ctx context.Context, program Program, upstream Upstream) (*Process, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return launch(ctx, program, upstream, SocketPath(os.Getuid()), 0, exe, []string{LauncherFlag})
}

func launch(ctx context.Context, program Program, upstream Upstream, socket string, helperUID uint32, exe string, barrierArgs []string) (*Process, error) {
	if os.Geteuid() == 0 {
		return nil, errors.New("请以普通用户运行桌面应用")
	}
	if err := program.validate(); err != nil {
		return nil, err
	}
	if err := upstream.validate(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	client, err := dialControl(ctx, socket, helperUID)
	if err != nil {
		return nil, err
	}
	succeeded := false
	defer func() {
		if !succeeded {
			client.conn.Close()
		}
	}()
	id := randomID()
	args := []string{"--user", "--scope", "--quiet", "--collect", "--expand-environment=no", "--unit=easyconnect-hub-" + id + ".scope", "--", exe}
	args = append(args, barrierArgs...)
	cmd := exec.Command("/usr/bin/systemd-run", args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	defer stdin.Close()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	defer stdout.Close()
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	// Wait closes StdoutPipe, so start the reaper only after startup responses
	// have been consumed (or their pipes explicitly closed on failure).
	defer func() { go func() { _ = cmd.Wait() }() }()
	stop := context.AfterFunc(ctx, func() { stdin.Close(); stdout.Close() })
	defer stop()
	if err := writeFrame(stdin, launchMessage{Program: &program}); err != nil {
		return nil, err
	}
	r := bufio.NewReaderSize(stdout, maxFrame)
	var ready launchMessage
	if err := readFrame(r, &ready); err != nil {
		return nil, fmt.Errorf("软件启动组未就绪：%w", err)
	}
	if ready.Error != "" {
		return nil, errors.New(ready.Error)
	}
	if ready.PID <= 0 || ready.StartTime == 0 {
		return nil, errors.New("capture: invalid launch barrier")
	}
	res, err := client.call(ctx, frame{Type: "attach", Attach: &attachRequest{ID: id, PID: ready.PID, StartTime: ready.StartTime, Upstream: upstream}})
	if err != nil {
		return nil, err
	}
	if !res.Active || res.ID != id {
		return nil, errors.New("capture: helper did not attach launch scope")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := writeFrame(stdin, launchMessage{Release: true}); err != nil {
		return nil, err
	}
	var started launchMessage
	if err := readFrame(r, &started); err != nil {
		return nil, err
	}
	if started.Error != "" {
		return nil, errors.New(started.Error)
	}
	if started.PID <= 0 {
		return nil, errors.New("capture: program did not start")
	}
	p := &Process{PID: started.PID, id: id, client: client, done: make(chan struct{})}
	succeeded = true
	go p.heartbeat()
	return p, nil
}
