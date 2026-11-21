package localapps

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/ehZyiL/connect-hub/internal/model"
)

// BrowserSupervisorFlag starts a lightweight mode of the same executable.
// It outlives the GUI when necessary, so closing the GUI does not close a
// user's browser or leave its temporary profile behind after the browser exits.
const BrowserSupervisorFlag = "--managed-proxy-browser"

type browserRequest struct {
	Executable string `json:"executable"`
	Proxy      string `json:"proxy"`
	URL        string `json:"url"`
	WorkDir    string `json:"workDir,omitempty"`
}

type browserReady struct {
	PID   int    `json:"pid,omitempty"`
	Error string `json:"error,omitempty"`
}

func validateProxy(address string) error {
	host, port, err := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	n, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || ip == nil || !ip.IsLoopback() || n < 1 || n > 65535 {
		return errors.New("需要有效的本地回环 SOCKS5 代理地址")
	}
	return nil
}

// RunBrowserSupervisor owns one browser and removes its temporary profile only
// after that browser exits. The parent sends one JSON request and closes stdin;
// no credentials or shell commands are involved. Only the ready event is sent
// to stdout; browser output is discarded.
func RunBrowserSupervisor(input io.Reader, output io.Writer) error {
	var req browserRequest
	if err := json.NewDecoder(io.LimitReader(input, 64<<10)).Decode(&req); err != nil {
		return errors.New("无法读取浏览器启动参数")
	}
	report := func(err error) error {
		_ = json.NewEncoder(output).Encode(browserReady{Error: err.Error()})
		return err
	}
	p := model.LocalApp{ID: "browser", Name: "browser", PointID: "point", Mode: model.LocalAppBrowser, Executable: req.Executable, URL: req.URL, WorkDir: req.WorkDir}
	p.Normalize()
	if err := p.Validate(); err != nil {
		return report(err)
	}
	if err := validateProxy(req.Proxy); err != nil {
		return report(err)
	}
	if p.Executable == "" {
		return report(errors.New("没有可用的 Chromium 浏览器"))
	}
	dir, err := os.MkdirTemp("", "easyconnect-browser-")
	if err != nil {
		return report(err)
	}
	defer os.RemoveAll(dir)
	exts := populateUserData(p.Executable, dir)
	args := []string{
		"--proxy-server=socks5://" + req.Proxy,
		"--user-data-dir=" + dir,
		"--show-bookmarks-bar",
		"--enable-extensions",
		"--no-first-run", "--no-default-browser-check", "--disable-quic",
		"--dns-over-https-mode=off", "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
	}
	if len(exts) > 0 {
		args = append(args, "--load-extension="+strings.Join(exts, ","))
	}
	args = append(args, p.URL)
	cmd := exec.Command(p.Executable, args...)
	cmd.Dir = p.WorkDir
	if err := cmd.Start(); err != nil {
		return report(fmt.Errorf("启动浏览器失败：%w", err))
	}
	// Do not terminate an already started browser if the GUI disappeared.
	_ = json.NewEncoder(output).Encode(browserReady{PID: cmd.Process.Pid})
	return cmd.Wait()
}

type browserProcess struct {
	cmd *exec.Cmd
	pid int
}

func launchBrowser(ctx context.Context, p model.LocalApp, proxyAddress string) (*browserProcess, error) {
	if err := validateProxy(proxyAddress); err != nil {
		return nil, err
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	// Cancellation bounds startup below. Once ready, the supervisor must
	// outlive the manager so it can clean the profile after the browser exits.
	cmd := exec.Command(exe, BrowserSupervisorFlag)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		return nil, err
	}
	err = json.NewEncoder(stdin).Encode(browserRequest{Executable: p.Executable, Proxy: proxyAddress, URL: p.URL, WorkDir: p.WorkDir})
	_ = stdin.Close()

	type decodeResult struct {
		ready browserReady
		err   error
	}
	ch := make(chan decodeResult, 1)
	go func() {
		var ready browserReady
		dErr := json.NewDecoder(bufio.NewReader(io.LimitReader(stdout, 64<<10))).Decode(&ready)
		_ = stdout.Close()
		ch <- decodeResult{ready: ready, err: dErr}
	}()

	var ready browserReady
	select {
	case res := <-ch:
		err = res.err
		ready = res.ready
	case <-time.After(15 * time.Second):
		err = errors.New("浏览器启动超时")
	case <-ctx.Done():
		err = ctx.Err()
	}

	if err != nil || ready.Error != "" || ready.PID <= 0 {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
		if err != nil {
			return nil, err
		}
		if ready.Error != "" {
			return nil, errors.New(ready.Error)
		}
		return nil, errors.New("浏览器启动器未返回有效状态")
	}
	return &browserProcess{cmd: cmd, pid: ready.PID}, nil
}

// OpenBrowser is also used by the original quick-launch button.
func OpenBrowser(executable, proxyAddress, target string) error {
	p := model.LocalApp{ID: "quick", Name: "browser", PointID: "point", Mode: model.LocalAppBrowser, Executable: executable, URL: target}
	p.Normalize()
	if err := p.Validate(); err != nil {
		return err
	}
	b, err := launchBrowser(context.Background(), p, proxyAddress)
	if err != nil {
		return err
	}
	go func() { _ = b.cmd.Wait() }()
	return nil
}
