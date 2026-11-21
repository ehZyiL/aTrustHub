package vpn

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/qy/easyconnect/internal/model"
	hubproxy "github.com/qy/easyconnect/internal/proxy"
	"github.com/qy/easyconnect/internal/workeripc"
	"golang.org/x/net/proxy"
)

func NewProtocolConnector(options ZJUOptions) Connector {
	atrust := NewZJUConnector(options)
	easy := NewEasyConnectConnector("")
	return func(ctx context.Context, point model.AccessPoint, creds Credentials) (Session, error) {
		if point.Protocol == model.ProtocolEasyConnect {
			return easy(ctx, point, creds)
		}
		return atrust(ctx, point, creds)
	}
}

// workerPath deliberately avoids PATH or the current working directory.
func workerPath() (string, error) {
	if configured := os.Getenv("EASYCONNECT_WORKER"); configured != "" {
		return filepath.Abs(configured)
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	name := "easyconnect-worker"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	// core/ 是当前发布的布局（避免用户直接双击内部程序）；平铺位置留给
	// 开发构建目录和拆分之前的旧包。
	dir := filepath.Dir(exe)
	for _, path := range []string{
		filepath.Join(dir, "core", name),
		filepath.Join(dir, name),
	} {
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			return path, nil
		}
	}
	return "", errors.New("缺少 easyconnect-worker 核心，请解压完整安装包（easyconnect-worker.exe 位于 core 目录），或设置 EASYCONNECT_WORKER")
}

func NewEasyConnectConnector(path string) Connector {
	return func(ctx context.Context, point model.AccessPoint, creds Credentials) (Session, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		bin := path
		if bin == "" {
			var err error
			bin, err = workerPath()
			if err != nil {
				return nil, err
			}
		}
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return nil, err
		}
		password := hex.EncodeToString(secret)
		cmd := exec.Command(bin)
		hideWorkerCmd(cmd)
		s := &processSession{cmd: cmd, session: model.NewID(), events: make(chan workeripc.Message, 8), done: make(chan struct{}), stopping: make(chan struct{}), dnsPending: make(map[string]chan workeripc.Message), dnsSlots: make(chan struct{}, workeripc.MaxDNSRequests), outgoing: make(chan workerWrite, 32)}
		// Lifetime is explicit: the login context expires after authentication.
		s.cmd.Stderr = io.Discard
		stdin, err := s.cmd.StdinPipe()
		if err != nil {
			return nil, err
		}
		s.stdin, s.encoder = stdin, json.NewEncoder(stdin)
		stdout, err := s.cmd.StdoutPipe()
		if err != nil {
			_ = stdin.Close()
			return nil, err
		}
		if err = s.cmd.Start(); err != nil {
			_ = stdin.Close()
			_ = stdout.Close()
			return nil, fmt.Errorf("无法启动 EasyConnect 核心：%w", err)
		}
		go s.read(stdout)
		go s.write()
		connected := false
		defer func() {
			if !connected {
				_ = s.Close()
			}
		}()
		if err := s.send(ctx, workeripc.Message{Type: "start", Config: &workeripc.Config{
			Server: net.JoinHostPort(point.Server, strconv.Itoa(point.Port)), Username: point.Username, Password: creds.Login,
			RemoteDNS: point.RemoteDNS, InternalDomains: point.InternalDomains, CertificateSHA256: point.CertificateSHA256,
			SocksUser: "hub", SocksPassword: password,
		}}); err != nil {
			return nil, err
		}
		for {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-s.done:
				return nil, s.Err()
			case m := <-s.events:
				switch m.Type {
				case "challenge":
					if creds.Challenge == nil {
						return nil, errors.New("此网关需要验证码，请在桌面界面连接")
					}
					answer, err := creds.Challenge(ctx, Challenge{ID: m.ChallengeID, Kind: m.Kind, Image: m.Image})
					if err != nil {
						return nil, err
					}
					if err = s.send(ctx, workeripc.Message{Type: "answer", ChallengeID: m.ChallengeID, Answer: answer}); err != nil {
						return nil, err
					}
				case "ready":
					if err := s.configureReady(m, password); err != nil {
						return nil, err
					}
					var apps []App
					if m.Resources != nil {
						for i, r := range m.Resources.IPRules {
							if r.Min == r.Max && r.PortMin == r.PortMax && r.PortMin > 0 {
								apps = append(apps, App{
									ID:   fmt.Sprintf("ip-rule-%d", i),
									Name: fmt.Sprintf("%s:%d", r.Min, r.PortMin),
									Addresses: []AppAddress{
										{Protocol: "tcp", Host: r.Min, Port: strconv.Itoa(r.PortMin)},
									},
								})
							}
						}
					}
					s.info = SessionInfo{ClientIP: m.ClientIP, DNSServer: m.DNSServer, Resources: m.Resources, Apps: apps, HealthTarget: point.HealthTarget}
					if err := ctx.Err(); err != nil {
						return nil, err
					}
					connected = true
					return s, nil
				}
			}
		}
	}
}

type processSession struct {
	cmd         *exec.Cmd
	stdin       io.WriteCloser
	encoder     *json.Encoder
	outgoing    chan workerWrite
	session     string
	events      chan workeripc.Message
	done        chan struct{}
	stopping    chan struct{}
	closeOnce   sync.Once
	errMu       sync.Mutex
	err         error
	info        SessionInfo
	dialer      proxy.ContextDialer
	dnsMu       sync.Mutex
	dnsSequence uint64
	dnsPending  map[string]chan workeripc.Message
	dnsSlots    chan struct{}
	flows       atomic.Pointer[flowDials]
}

var ErrStrictVPNUnavailable = errors.New("当前核心不支持严格 VPN 拨号，请更新配套核心")

func (s *processSession) configureReady(m workeripc.Message, password string) error {
	validAddress := func(address string) bool {
		host, port, err := net.SplitHostPort(address)
		n, portErr := strconv.Atoi(port)
		return err == nil && portErr == nil && n > 0 && n <= 65535 && host == "127.0.0.1"
	}
	if !validAddress(m.Address) {
		return errors.New("核心返回了无效的本地代理地址")
	}
	capabilities := make(map[string]bool)
	for _, capability := range m.Capabilities {
		capabilities[capability] = true
	}
	strict := capabilities["strict_vpn"]
	if capabilities[workeripc.StrictUDP] && !strict {
		return ErrStrictUDPUnavailable
	}
	prepared := capabilities["flow_prepare"] && capabilities["flow_cancel"] && m.FlowReporting
	if strict && (!prepared || !validAddress(m.VPNAddress) || m.VPNAddress == m.Address) {
		return ErrStrictVPNUnavailable
	}
	d, err := hubproxy.NewSOCKSDialer(m.Address, &proxy.Auth{User: "hub", Password: password})
	if err != nil {
		return err
	}
	s.dialer = d
	if m.FlowReporting {
		f := newFlowDials(m.Address, "hub", password)
		f.prepare = prepared
		if strict {
			f.vpnAddress = m.VPNAddress
			if capabilities[workeripc.StrictUDP] {
				f.strictUDP, f.udpSlots = true, make(chan struct{}, workeripc.MaxFlowRequests)
			}
		}
		s.flows.Store(f)
	}
	return nil
}

type workerWrite struct {
	ctx     context.Context
	message workeripc.Message
	result  chan error
}

func (s *processSession) send(ctx context.Context, m workeripc.Message) error {
	req := workerWrite{ctx: ctx, message: m, result: make(chan error, 1)}
	select {
	case s.outgoing <- req:
	case <-ctx.Done():
		return ctx.Err()
	case <-s.stopping:
		return net.ErrClosed
	case <-s.done:
		return s.Err()
	}
	select {
	case err := <-req.result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-s.stopping:
		return net.ErrClosed
	case <-s.done:
		return s.Err()
	}
}

func (s *processSession) write() {
	for {
		var req workerWrite
		select {
		case <-s.stopping:
			return
		case <-s.done:
			return
		case req = <-s.outgoing:
		}
		if err := req.ctx.Err(); err != nil {
			req.result <- err
			continue
		}
		req.message.Version, req.message.Session = workeripc.Version, s.session
		if pipe, ok := s.stdin.(interface{ SetWriteDeadline(time.Time) error }); ok {
			_ = pipe.SetWriteDeadline(time.Now().Add(2 * time.Second))
		}
		err := s.encoder.Encode(req.message)
		req.result <- err
		if err != nil {
			s.setError(errors.New("EasyConnect 核心通信写入失败"))
			_ = s.cmd.Process.Kill()
			return
		}
	}
}

func (s *processSession) read(r io.Reader) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), workeripc.MaxMessage)
	ready := false
	received := false
	for scanner.Scan() {
		var m workeripc.Message
		if json.Unmarshal(scanner.Bytes(), &m) != nil || m.Version != workeripc.Version || m.Session != s.session {
			s.setError(errors.New("EasyConnect 核心通信格式不兼容"))
			_ = s.cmd.Process.Kill()
			break
		}
		received = true
		if m.Type == "error" {
			s.setError(errors.New(m.Error))
			continue
		}
		if m.Type == "dns_result" && ready {
			s.dnsMu.Lock()
			if pending := s.dnsPending[m.RequestID]; pending != nil {
				select {
				case pending <- m:
				default:
				}
			}
			s.dnsMu.Unlock()
			continue
		}
		if m.Type == "flow_result" && ready {
			// Reports are advisory. An invalid target from a local proxy client
			// must not terminate the VPN; discard untrusted report contents and
			// let that dial display an unknown path after the bounded wait.
			if flows := s.flows.Load(); flows != nil {
				flows.deliver(m)
			}
			continue
		}
		if m.Type == "flow_ready" && ready {
			if flows := s.flows.Load(); flows != nil {
				flows.deliverReady(m)
			}
			continue
		}
		if ready || (m.Type != "challenge" && m.Type != "ready") {
			s.setError(errors.New("EasyConnect 核心返回了无效的控制事件"))
			_ = s.cmd.Process.Kill()
			break
		}
		ready = m.Type == "ready"
		select {
		case s.events <- m:
		case <-s.stopping:
		default:
			s.setError(errors.New("EasyConnect 核心控制事件过多"))
			_ = s.cmd.Process.Kill()
		}
	}
	if scanner.Err() != nil {
		s.setError(errors.New("EasyConnect 核心通信中断"))
		_ = s.cmd.Process.Kill()
	}
	waitErr := s.cmd.Wait()
	if !received {
		s.setError(fmt.Errorf("EasyConnect 核心尚未完成协议握手就退出（退出码 %d）；请完整替换 GUI、worker 和网络助手的配套完整测试包，或运行 test-worker.ps1 检查版本", s.cmd.ProcessState.ExitCode()))
	} else if waitErr != nil {
		s.setError(errors.New("EasyConnect 核心已退出，请重新连接"))
	}
	close(s.done)
}

func (s *processSession) setError(err error) {
	s.errMu.Lock()
	defer s.errMu.Unlock()
	if s.err == nil {
		s.err = err
	}
}
func (s *processSession) Err() error {
	s.errMu.Lock()
	defer s.errMu.Unlock()
	if s.err == nil {
		return errors.New("EasyConnect 连接已结束")
	}
	return s.err
}
func (s *processSession) Done() <-chan struct{} { return s.done }
func (s *processSession) Info() SessionInfo {
	return cloneSessionInfo(s.info)
}
func (s *processSession) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" {
		return nil, errors.New("EasyConnect 桌面代理目前只支持 TCP")
	}
	select {
	case <-s.done:
		return nil, s.Err()
	case <-s.stopping:
		return nil, net.ErrClosed
	default:
	}
	// SOCKS receives the original hostname; the worker applies split DNS.
	if s.flows.Load() != nil {
		return s.dialFlow(ctx, addr)
	}
	return s.dialer.DialContext(ctx, "tcp", addr)
}

func (s *processSession) DialVPN(ctx context.Context, network, addr string) (net.Conn, error) {
	if network == "udp" || network == "udp4" {
		if !s.SupportsStrictUDP() {
			return nil, ErrStrictUDPUnavailable
		}
		return s.dialFlowTransport(ctx, addr, s.flows.Load().vpnAddress, true)
	}
	if network != "tcp" && network != "tcp4" {
		return nil, errors.New("严格 VPN 入口目前只支持 IPv4 TCP")
	}
	f := s.flows.Load()
	if f == nil || f.vpnAddress == "" || !f.prepare {
		return nil, ErrStrictVPNUnavailable
	}
	return s.dialFlowAddress(ctx, addr, f.vpnAddress)
}

var ErrStrictUDPUnavailable = errors.New("所属网关没有可用的 IPv4 UDP 隧道，或核心版本不匹配")

func (s *processSession) SupportsStrictUDP() bool {
	f := s.flows.Load()
	return f != nil && f.strictUDP
}

func (s *processSession) TrimMemory() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return s.send(ctx, workeripc.Message{Type: "trim_memory"})
}

func (s *processSession) Close() error {
	s.closeOnce.Do(func() {
		close(s.stopping)
		_ = s.stdin.Close() // EOF cancels authentication and closes all resources
		select {
		case <-s.done:
		case <-time.After(3 * time.Second):
			_ = s.cmd.Process.Kill()
			<-s.done
		}
	})
	return nil
}

var _ Prober = (*processSession)(nil)

func (s *processSession) Probe(ctx context.Context) error {
	if err := s.ProbeDNS(ctx); !errors.Is(err, errProbeUnavailable) {
		return err
	}
	if target := healthTarget(s.info); target != "" {
		return probeSession(ctx, s, target)
	}
	return errProbeUnavailable
}

func (s *processSession) ProbeDNS(ctx context.Context) error {
	select {
	case <-s.done:
		return s.Err()
	case <-s.stopping:
		return net.ErrClosed
	default:
	}

	// 1. If remote DNS or internal domains are available, probe via tunnel DNS query.
	hasDNS := s.info.DNSServer != "" || (s.info.Resources != nil && (s.info.Resources.DNSServer != "" || len(s.info.Resources.InternalDomains) > 0))
	if hasDNS {
		name := "dns.test."
		if s.info.Resources != nil && len(s.info.Resources.InternalDomains) > 0 {
			name = dns.Fqdn(s.info.Resources.InternalDomains[0])
		}
		q := new(dns.Msg)
		q.SetQuestion(name, dns.TypeSOA)
		packed, err := q.Pack()
		if err != nil {
			return err
		}
		reply, err := s.ExchangeDNS(ctx, packed)
		if err != nil {
			return fmt.Errorf("隧道 DNS 探测失败：%w", err)
		}
		res := new(dns.Msg)
		if err := res.Unpack(reply); err != nil {
			return fmt.Errorf("隧道 DNS 应答解析失败：%w", err)
		}
		if res.Rcode != dns.RcodeSuccess && res.Rcode != dns.RcodeNameError {
			return fmt.Errorf("隧道 DNS 返回 %s", dns.RcodeToString[res.Rcode])
		}
		return nil
	}
	return errProbeUnavailable
}
