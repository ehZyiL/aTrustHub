package process

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/ehzyil/connect-hub/internal/relay"
	"github.com/ehzyil/connect-hub/internal/relay/contract"
	vpncontract "github.com/ehzyil/connect-hub/internal/vpn/contract"
	"github.com/ehzyil/connect-hub/internal/workeripc"
)

type importedSession struct {
	cmd         *exec.Cmd
	stdin       io.WriteCloser
	writeMu     sync.Mutex
	infoMu      sync.RWMutex
	info        vpncontract.SessionInfo
	epoch       uint64
	revision    string
	point       model.AccessPoint
	save        func(string, contract.RelaySnapshotSource, *workeripc.ResourceSnapshot) error
	data        *remoteSource
	updates     chan vpncontract.SessionUpdate
	events      chan event
	done        chan struct{}
	readDone    chan struct{}
	errMu       sync.RWMutex
	endErr      error
	once        sync.Once
	updatesOnce sync.Once
	closed      atomic.Bool
	seq         atomic.Uint64
}

var (
	_ vpncontract.Session        = (*importedSession)(nil)
	_ vpncontract.StrictSession  = (*importedSession)(nil)
	_ vpncontract.SessionWatcher = (*importedSession)(nil)
	_ vpncontract.SessionUpdater = (*importedSession)(nil)
	_ vpncontract.DNSExchanger   = (*importedSession)(nil)
)

// NewConnector runs imported LAN relay sessions in connect-hub-relay. A missing
// or mismatched component is a hard error; the Hub never reconnects directly.
func NewConnector(executable string, saveSnapshot func(string, contract.RelaySnapshotSource, *workeripc.ResourceSnapshot) error) vpncontract.Connector {
	return func(ctx context.Context, point model.AccessPoint, creds vpncontract.Credentials) (vpncontract.Session, error) {
		if point.Protocol != model.ProtocolLANRelay || point.Relay == nil || point.Relay.Version != 1 {
			return nil, errors.New("分享接入点身份无效或版本不受支持")
		}
		if creds.Login == "" {
			return nil, errors.New("分享口令缺失，请重新导入")
		}
		if executable == "" {
			return nil, errors.New("缺少局域网分享组件 connect-hub-relay")
		}
		return startImported(ctx, executable, point, creds.Login, saveSnapshot)
	}
}

func startImported(ctx context.Context, executable string, point model.AccessPoint, token string, save func(string, contract.RelaySnapshotSource, *workeripc.ResourceSnapshot) error) (*importedSession, error) {
	probeCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	probe := exec.CommandContext(probeCtx, executable, "--protocol-version")
	out, err := probe.Output()
	cancel()
	if err != nil || strings.TrimSpace(string(out)) != ProtocolVersion {
		return nil, errors.New("局域网分享组件版本不兼容，请重新安装完整程序")
	}
	cmd := exec.Command(executable)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("局域网分享组件无法启动：%w", err)
	}
	s := &importedSession{cmd: cmd, stdin: stdin, point: point, save: save,
		updates: make(chan vpncontract.SessionUpdate, 4), events: make(chan event, 4), done: make(chan struct{}), readDone: make(chan struct{})}
	go s.readEvents(stdout)
	go s.wait()
	start := startup{Version: ProtocolVersion, Mode: "import", Point: point, Token: token}
	if err := json.NewEncoder(stdin).Encode(start); err != nil {
		_ = s.stop()
		return nil, fmt.Errorf("局域网分享组件握手失败：%w", err)
	}
	select {
	case e := <-s.events:
		if e.Kind != "ready" || e.Info == nil || e.Port <= 0 || e.Port > 65535 || e.Token == "" {
			_ = s.stop()
			if e.Error != "" {
				return nil, errors.New(e.Error)
			}
			return nil, errors.New("局域网分享组件返回无效会话")
		}
		s.info = vpncontract.CloneInfo(*e.Info)
		s.epoch, s.revision = e.Epoch, e.Revision
		s.data = newBrokerClient(net.JoinHostPort("127.0.0.1", fmt.Sprint(e.Port)), e.Token)
		if save != nil && point.Relay != nil {
			identity := contract.RelaySnapshotSource{ShareID: point.Relay.ShareID, Fingerprint: point.Relay.CertificateSHA256}
			if err := save(point.ID, identity, s.info.Resources); err != nil {
				_ = s.stop()
				return nil, fmt.Errorf("历史归属无法保存：%w", err)
			}
		}
		go s.consumeEvents()
		return s, nil
	case <-ctx.Done():
		_ = s.stop()
		return nil, ctx.Err()
	case <-s.done:
		s.errMu.RLock()
		waitErr := s.endErr
		s.errMu.RUnlock()
		if waitErr == nil {
			waitErr = errors.New("分享组件在会话建立前退出")
		}
		return nil, waitErr
	case <-time.After(relay.FirstConnectBudget + time.Second):
		_ = s.stop()
		return nil, errors.New("连接分享组件超时")
	}
}

func (s *importedSession) consumeEvents() {
	defer s.updatesOnce.Do(func() { close(s.updates) })
	for {
		select {
		case <-s.done:
			return
		case e := <-s.events:
			s.applyEvent(e)
		}
	}
}

func (s *importedSession) readEvents(r io.Reader) {
	defer close(s.readDone)
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64<<10), contract.MaxSnapshotBytes+(128<<10))
	for scanner.Scan() {
		var e event
		if json.Unmarshal(scanner.Bytes(), &e) != nil {
			continue
		}
		select {
		case s.events <- e:
		default:
			if e.Kind == "update" {
				select {
				case <-s.events:
				default:
				}
				select {
				case s.events <- e:
				default:
				}
			}
		}
	}
}

func (s *importedSession) wait() {
	err := s.cmd.Wait()
	<-s.readDone
	s.finish(err)
}

func (s *importedSession) finish(err error) {
	s.once.Do(func() {
		s.errMu.Lock()
		if s.endErr == nil {
			s.endErr = err
		}
		s.errMu.Unlock()
		close(s.done)
	})
}

func (s *importedSession) applyEvent(e event) {
	if e.Kind == "ended" {
		if e.Error != "" {
			s.errMu.Lock()
			s.endErr = errors.New(e.Error)
			s.errMu.Unlock()
		}
		return
	}
	if e.Kind != "update" || e.Info == nil {
		return
	}
	info := vpncontract.CloneInfo(*e.Info)
	if s.save != nil && s.point.Relay != nil {
		identity := contract.RelaySnapshotSource{ShareID: s.point.Relay.ShareID, Fingerprint: s.point.Relay.CertificateSHA256}
		if err := s.save(s.point.ID, identity, info.Resources); err != nil {
			s.errMu.Lock()
			s.endErr = fmt.Errorf("资源归属无法保存：%w", err)
			s.errMu.Unlock()
			_ = s.send(command{Operation: "stop"})
			return
		}
	}
	s.infoMu.Lock()
	s.info, s.epoch, s.revision = info, e.Epoch, e.Revision
	s.infoMu.Unlock()
	seq := s.seq.Add(1)
	update := vpncontract.SessionUpdate{Sequence: seq, Info: vpncontract.CloneInfo(info)}
	select {
	case s.updates <- update:
	default:
		select {
		case <-s.updates:
		default:
		}
		select {
		case s.updates <- update:
		default:
		}
	}
}

func (s *importedSession) Info() vpncontract.SessionInfo {
	s.infoMu.RLock()
	defer s.infoMu.RUnlock()
	return vpncontract.CloneInfo(s.info)
}

func (s *importedSession) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	return s.DialVPN(ctx, network, addr)
}

func (s *importedSession) DialVPN(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" {
		return nil, vpncontract.ErrStrictVPNUnavailable
	}
	if s.closed.Load() {
		return nil, net.ErrClosed
	}
	s.infoMu.RLock()
	revision := s.revision
	s.infoMu.RUnlock()
	return s.data.DialVPN(ctx, revision, addr)
}

func (s *importedSession) ExchangeDNS(ctx context.Context, query []byte) ([]byte, error) {
	if s.closed.Load() {
		return nil, net.ErrClosed
	}
	s.infoMu.RLock()
	revision := s.revision
	s.infoMu.RUnlock()
	return s.data.ExchangeDNS(ctx, revision, query)
}

func (s *importedSession) Done() <-chan struct{}                     { return s.done }
func (s *importedSession) Updates() <-chan vpncontract.SessionUpdate { return s.updates }

func (s *importedSession) Err() error {
	s.errMu.RLock()
	defer s.errMu.RUnlock()
	return s.endErr
}

func (s *importedSession) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	err := s.send(command{Operation: "stop"})
	select {
	case <-s.done:
	case <-time.After(8 * time.Second):
		_ = s.cmd.Process.Kill()
		<-s.done
	}
	_ = s.stdin.Close()
	return err
}

func (s *importedSession) stop() error {
	_ = s.send(command{Operation: "stop"})
	_ = s.stdin.Close()
	_ = s.cmd.Process.Kill()
	select {
	case <-s.done:
	case <-time.After(3 * time.Second):
	}
	return nil
}

func (s *importedSession) send(c command) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return json.NewEncoder(s.stdin).Encode(c)
}
