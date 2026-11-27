package process

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/ehzyil/connect-hub/internal/relay"
	"github.com/ehzyil/connect-hub/internal/relay/contract"
)

func (p *processServer) PairingSupported() bool { return p.pairing }
func (p *processServer) PairControl(ctx context.Context, c contract.PairCommand) (contract.PairView, error) {
	if err := ctx.Err(); err != nil {
		return contract.PairView{}, err
	}
	if !p.pairing {
		return contract.PairView{}, errors.New("pairing_unsupported: 请更新分享组件")
	}
	id := p.seq.Add(1)
	ch := make(chan event, 1)
	p.rpcMu.Lock()
	p.rpc[id] = ch
	p.rpcMu.Unlock()
	defer func() { p.rpcMu.Lock(); delete(p.rpc, id); p.rpcMu.Unlock() }()
	if err := p.sendContext(ctx, command{Operation: "pair-control", ID: id, PairCommand: &c}); err != nil {
		return contract.PairView{}, err
	}
	select {
	case e := <-ch:
		v := contract.PairView{}
		if e.PairView != nil {
			v = *e.PairView
		}
		if e.Error != "" {
			return v, errors.New(e.Error)
		}
		return v, nil
	case <-ctx.Done():
		return contract.PairView{}, ctx.Err()
	case <-p.done:
		return contract.PairView{}, errors.New("配对组件已退出")
	}
}

func (b *broker) deviceRecords(w http.ResponseWriter, r *http.Request) {
	if !b.authorized(w, r) {
		return
	}
	if b.devices == nil {
		http.Error(w, "pairing unavailable", http.StatusNotImplemented)
		return
	}
	switch r.Method {
	case http.MethodGet:
		devices, err := b.devices.LoadDevices(r.Context(), b.shareID)
		if err != nil {
			http.Error(w, "device load failed", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(devices)
	case http.MethodPost:
		data, err := io.ReadAll(io.LimitReader(r.Body, (128<<10)+1))
		if err != nil || len(data) > 128<<10 {
			http.Error(w, "device limit", http.StatusBadRequest)
			return
		}
		var devices []contract.PairedDevice
		if json.Unmarshal(data, &devices) != nil || len(devices) > contract.MaxPairedDevices {
			http.Error(w, "invalid devices", http.StatusBadRequest)
			return
		}
		if b.devices.SaveDevices(r.Context(), b.shareID, devices) != nil {
			http.Error(w, "device save failed", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method", http.StatusMethodNotAllowed)
	}
}

type remoteDeviceStore struct {
	source  *remoteSource
	shareID string
}

func (s remoteDeviceStore) LoadDevices(ctx context.Context, sid string) ([]contract.PairedDevice, error) {
	if sid != s.shareID {
		return nil, errors.New("device scope mismatch")
	}
	resp, err := s.source.request(ctx, http.MethodGet, "/devices", nil, "")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("device load failed")
	}
	var devices []contract.PairedDevice
	err = json.NewDecoder(io.LimitReader(resp.Body, 128<<10)).Decode(&devices)
	return devices, err
}
func (s remoteDeviceStore) SaveDevices(ctx context.Context, sid string, devices []contract.PairedDevice) error {
	if sid != s.shareID {
		return errors.New("device scope mismatch")
	}
	data, err := json.Marshal(devices)
	if err != nil {
		return err
	}
	resp, err := s.source.request(ctx, http.MethodPost, "/devices", bytes.NewReader(data), "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return errors.New("device save failed")
	}
	return nil
}

// PairAttempt is an independently owned sidecar. Closing the dialog closes
// its stdin and process; no PAKE key or PIN appears in process arguments.
type PairAttempt struct {
	cmd       *exec.Cmd
	in        io.WriteCloser
	mu        sync.Mutex
	updates   chan contract.PairProgress
	acks      chan error
	done      chan struct{}
	closeOnce sync.Once
}

func StartPairing(ctx context.Context, executable string, target contract.PairTarget, pin string) (contract.PairAttempt, error) {
	if executable == "" {
		return nil, errors.New("缺少分享组件")
	}
	probeCtx, finishProbe := context.WithTimeout(ctx, 4*time.Second)
	probe := newCommandContext(probeCtx, executable, "--protocol-version")
	out, err := probe.Output()
	finishProbe()
	if err != nil || strings.TrimSpace(string(out)) != ProtocolVersion {
		return nil, errors.New("分享组件版本不兼容")
	}
	cmd := newCommand(executable)
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	outPipe, err := cmd.StdoutPipe()
	if err != nil {
		in.Close()
		return nil, err
	}
	cmd.Stderr = io.Discard
	if err = cmd.Start(); err != nil {
		return nil, err
	}
	p := &PairAttempt{cmd: cmd, in: in, updates: make(chan contract.PairProgress, 8), acks: make(chan error, 1), done: make(chan struct{})}
	go func() {
		defer close(p.updates)
		scan := bufio.NewScanner(outPipe)
		scan.Buffer(make([]byte, 1024), 32<<10)
		for scan.Scan() {
			var e event
			if json.Unmarshal(scan.Bytes(), &e) != nil {
				continue
			}
			if e.Kind == "pair-ack" {
				var err error
				if e.Error != "" {
					err = errors.New(e.Error)
				}
				select {
				case p.acks <- err:
				default:
				}
				continue
			}
			if e.PairProgress != nil {
				select {
				case p.updates <- *e.PairProgress:
				default:
				}
			}
		}
		_ = cmd.Wait()
		close(p.done)
	}()
	// Token is private stdin IPC, reused here as the short-lived PIN input.
	if err = json.NewEncoder(in).Encode(startup{Version: ProtocolVersion, Mode: "pair", PairTarget: &target, Token: pin}); err != nil {
		p.Close()
		return nil, err
	}
	go func() {
		select {
		case <-ctx.Done():
			_ = p.Close()
		case <-p.done:
		}
	}()
	return p, nil
}

func (p *PairAttempt) Updates() <-chan contract.PairProgress { return p.updates }
func (p *PairAttempt) Stored(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return json.NewEncoder(p.in).Encode(command{Operation: "pair-stored"})
}
func (p *PairAttempt) Ack(ctx context.Context) error {
	p.mu.Lock()
	err := json.NewEncoder(p.in).Encode(command{Operation: "pair-ack"})
	p.mu.Unlock()
	if err != nil {
		return err
	}
	select {
	case err := <-p.acks:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-p.done:
		select {
		case err := <-p.acks:
			return err
		default:
			return errors.New("配对领取响应丢失；已保存设备可重新连接验证")
		}
	}
}
func (p *PairAttempt) Close() error {
	p.closeOnce.Do(func() {
		p.mu.Lock()
		_ = p.in.Close()
		p.mu.Unlock()
		select {
		case <-p.done:
		case <-time.After(time.Second):
			_ = p.cmd.Process.Kill()
			<-p.done
		}
	})
	return nil
}

func runPairChild(cfg startup, scanner *bufio.Scanner, out io.Writer) error {
	if cfg.PairTarget == nil {
		return errors.New("pair target missing")
	}
	ctx, cancel := context.WithTimeout(context.Background(), contract.PairRequestLifetime+contract.PairHandshakeLifetime)
	defer cancel()
	// EOF must also cancel a blocked network handshake or approval wait.
	actions := make(chan command, 2)
	go func() {
		for scanner.Scan() {
			var c command
			if json.Unmarshal(scanner.Bytes(), &c) == nil {
				select {
				case actions <- c:
				case <-ctx.Done():
					return
				}
			}
		}
		cancel()
	}()
	write := func(e event) error { return json.NewEncoder(out).Encode(e) }
	handshakeCtx, finishHandshake := context.WithTimeout(ctx, contract.PairHandshakeLifetime)
	conn, err := relay.StartPairWithCheckpoint(handshakeCtx, *cfg.PairTarget, cfg.Token, func(code contract.ShareCode) error {
		if err := write(event{PairProgress: &contract.PairProgress{Request: contract.PairRequest{State: "saving"}, Code: &code}}); err != nil {
			return err
		}
		select {
		case c := <-actions:
			if c.Operation != "pair-stored" {
				return errors.New("device storage receipt missing")
			}
			return nil
		case <-handshakeCtx.Done():
			return handshakeCtx.Err()
		}
	})
	finishHandshake()
	cfg.Token = ""
	if err != nil {
		_ = write(event{PairProgress: &contract.PairProgress{Error: err.Error()}})
		return nil
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		v := conn.View()
		progress := contract.PairProgress{Request: v}
		if code, err := conn.Code(); err == nil {
			progress.Code = &code
		}
		if err = write(event{PairProgress: &progress}); err != nil {
			return err
		}
		if v.State == "rejected" || v.State == "expired" || v.State == "revoked" {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case c := <-actions:
			if c.Operation == "pair-ack" {
				err := conn.Ack()
				e := event{Kind: "pair-ack"}
				if err != nil {
					e.Error = err.Error()
				}
				_ = write(e)
				return nil
			}
		case <-ticker.C:
			if _, err = conn.Poll(); err != nil {
				progress := contract.PairProgress{Request: v, Error: "pair_channel_lost: 配对通道已断开，请重新申请；已保存设备可直接重连"}
				if !time.Now().Before(v.ExpiresAt) {
					progress.Request.State = "expired"
					progress.Error = "request_expired: 配对请求已超时；已批准并保存的设备仍可直接重连"
				}
				_ = write(event{PairProgress: &progress})
				return nil
			}
		}
	}
}
