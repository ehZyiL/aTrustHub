package process

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/ehzyil/connect-hub/internal/relay"
	"github.com/ehzyil/connect-hub/internal/relay/contract"
	vpncontract "github.com/ehzyil/connect-hub/internal/vpn/contract"
)

type testDeviceStore struct {
	mu      sync.Mutex
	devices []contract.PairedDevice
	fail    bool
}

func (s *testDeviceStore) LoadDevices(context.Context, string) ([]contract.PairedDevice, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]contract.PairedDevice(nil), s.devices...), nil
}
func (s *testDeviceStore) SaveDevices(_ context.Context, _ string, devices []contract.PairedDevice) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return errors.New("injected persistence failure")
	}
	s.devices = append([]contract.PairedDevice(nil), devices...)
	return nil
}

func waitPairState(t *testing.T, p contract.PairAttempt, state string) contract.PairProgress {
	t.Helper()
	deadline := time.NewTimer(8 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case update, ok := <-p.Updates():
			if !ok {
				t.Fatal("pair child exited before", state)
			}
			if update.Error != "" {
				t.Fatal(update.Error)
			}
			if update.Request.State == state {
				return update
			}
		case <-deadline.C:
			t.Fatal("pair state timeout", state)
		}
	}
}

func TestPairingSidecarPersistenceReceiptImportAndRestart(t *testing.T) {
	executable := buildRelayChild(t)
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	src := newTestSource(echo.Addr().String())
	defer src.Close()
	identity, err := relay.GenerateIdentity("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	store := &testDeviceStore{}
	opts := relay.ServerOptions{Identity: identity, Source: src, ShareID: "YWJjZGVmZ2hpamtsbW5vcA", Token: "legacy-token", ServerInstanceID: "pair-test", DeviceStore: store}
	server, err := start(opts, executable)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { server.Close(context.Background()) }()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	invite, err := server.PairControl(ctx, contract.PairCommand{Operation: "create"})
	if err != nil {
		t.Fatal(err)
	}
	if !server.PairingSupported() {
		t.Fatal("missing additive IPC capability")
	}
	target := contract.PairTarget{Host: "127.0.0.1", Port: server.Port(), ShareID: opts.ShareID, Name: "test-device", HostName: "test-host"}
	pair, err := StartPairing(ctx, executable, target, invite.PIN)
	if err != nil {
		t.Fatal(err)
	}
	defer pair.Close()
	saving := waitPairState(t, pair, "saving")
	if saving.Code == nil {
		t.Fatal("missing pre-confirmation credential")
	}
	if v, err := server.PairControl(ctx, contract.PairCommand{Operation: "list"}); err != nil || len(v.Requests) != 0 {
		t.Fatal("request existed before client persisted key", err)
	}
	if err = pair.Stored(ctx); err != nil {
		t.Fatal(err)
	}
	pending := waitPairState(t, pair, "pending")
	store.mu.Lock()
	store.fail = true
	store.mu.Unlock()
	v, err := server.PairControl(ctx, contract.PairCommand{Operation: "approve", ID: pending.Request.ID})
	if err == nil || v.Invitation.Approved != 0 || len(v.Devices) != 0 {
		t.Fatal("failed parent persistence was approved", err)
	}
	store.mu.Lock()
	store.fail = false
	store.mu.Unlock()
	if _, err = server.PairControl(ctx, contract.PairCommand{Operation: "approve", ID: pending.Request.ID}); err != nil {
		t.Fatal(err)
	}
	approved := waitPairState(t, pair, "approved")
	if approved.Code == nil {
		t.Fatal("missing approved credential")
	}
	if approved.Request.Verification != pending.Request.Verification {
		t.Fatal("session identity changed")
	}
	if err = pair.Ack(ctx); err != nil {
		t.Fatal(err)
	}
	code := *approved.Code
	point := model.AccessPoint{ID: "paired", Name: "paired", Protocol: model.ProtocolLANRelay, Server: target.Host, Port: target.Port, Relay: &model.RelayPointOptions{Version: 2, ShareID: opts.ShareID, CertificateSHA256: code.Fingerprint}}
	session, err := NewConnector(executable, nil)(ctx, point, vpncontract.Credentials{Login: code.Token})
	if err != nil {
		t.Fatal("v2 import sidecar", err)
	}
	defer session.Close()
	strict := session.(vpncontract.StrictSession)
	conn, err := strict.DialVPN(ctx, "tcp", "10.1.2.3:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err = conn.Write([]byte("paired-stream")); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, len("paired-stream"))
	if _, err = io.ReadFull(conn, data); err != nil || string(data) != "paired-stream" {
		t.Fatal("stream", err)
	}
	// Restart preserves grants but loses invitation and requests.
	if err = server.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	opts.Port = target.Port
	server, err = start(opts, executable)
	if err != nil {
		t.Fatal(err)
	}
	v, err = server.PairControl(ctx, contract.PairCommand{Operation: "list"})
	if err != nil {
		t.Fatal(err)
	}
	if v.Invitation != nil || len(v.Requests) != 0 || len(v.Devices) != 1 {
		t.Fatalf("restart state: %+v", v)
	}
	client, err := relay.NewClient(relay.ClientOptions{Code: code})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, _, err = client.Open(ctx); err != nil {
		t.Fatal("reconnect without PIN", err)
	}
	if _, err = server.PairControl(ctx, contract.PairCommand{Operation: "revoke", ID: pending.Request.DeviceID}); err != nil {
		t.Fatal(err)
	}
	if _, _, err = client.Open(ctx); err == nil {
		t.Fatal("sidecar revocation allowed reauth")
	}
}

type pairBlockingSource struct {
	*testSource
	started   chan struct{}
	cancelled chan struct{}
}

func (s *pairBlockingSource) DialVPN(ctx context.Context, revision, target string) (net.Conn, error) {
	close(s.started)
	<-ctx.Done()
	close(s.cancelled)
	return nil, ctx.Err()
}

func TestPairingSidecarCancellationAndRevocationAbortBrokerDial(t *testing.T) {
	executable := buildRelayChild(t)
	src := &pairBlockingSource{testSource: newTestSource(""), started: make(chan struct{}), cancelled: make(chan struct{})}
	defer src.Close()
	identity, _ := relay.GenerateIdentity("127.0.0.1")
	server, err := start(relay.ServerOptions{Identity: identity, Source: src, ShareID: "YWJjZGVmZ2hpamtsbW5vcA", Token: "legacy-token", DeviceStore: &testDeviceStore{}}, executable)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	invite, err := server.PairControl(ctx, contract.PairCommand{Operation: "create"})
	if err != nil {
		t.Fatal(err)
	}
	target := contract.PairTarget{Host: "127.0.0.1", Port: server.Port(), ShareID: "YWJjZGVmZ2hpamtsbW5vcA", Name: "device"}
	childCtx, cancelChild := context.WithCancel(ctx)
	unconfirmed, err := StartPairing(childCtx, executable, target, invite.PIN)
	if err != nil {
		t.Fatal(err)
	}
	waitPairState(t, unconfirmed, "saving")
	cancelChild()
	select {
	case <-unconfirmed.(*PairAttempt).done:
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled checkpoint did not stop child")
	}
	v, err := server.PairControl(ctx, contract.PairCommand{Operation: "list"})
	if err != nil || len(v.Requests) != 0 {
		t.Fatal("cancelled client checkpoint created host request", err)
	}
	var clients []*relay.Client
	var tokens []string
	var device string
	for range 2 {
		attempt, err := StartPairing(ctx, executable, target, invite.PIN)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { attempt.Close() })
		waitPairState(t, attempt, "saving")
		if err = attempt.Stored(ctx); err != nil {
			t.Fatal(err)
		}
		pending := waitPairState(t, attempt, "pending")
		if device == "" {
			device = pending.Request.DeviceID
		}
		if _, err = server.PairControl(ctx, contract.PairCommand{Operation: "approve", ID: pending.Request.ID}); err != nil {
			t.Fatal(err)
		}
		approved := waitPairState(t, attempt, "approved")
		client, err := relay.NewClient(relay.ClientOptions{Code: *approved.Code})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(client.Close)
		_, token, err := client.Open(ctx)
		if err != nil {
			t.Fatal(err)
		}
		clients, tokens = append(clients, client), append(tokens, token)
	}
	dialResult := make(chan error, 1)
	go func() {
		_, err := clients[0].Dial(ctx, tokens[0], src.snapshot.Epoch, src.snapshot.Revision, "10.1.2.3:443")
		dialResult <- err
	}()
	select {
	case <-src.started:
	case <-time.After(3 * time.Second):
		t.Fatal("dial never reached parent broker source")
	}
	if _, err = server.PairControl(ctx, contract.PairCommand{Operation: "revoke", ID: device}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-src.cancelled:
	case <-time.After(3 * time.Second):
		t.Fatal("device revocation did not cancel pending broker dial")
	}
	select {
	case err := <-dialResult:
		if err == nil {
			t.Fatal("revoked pending dial succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("pending client dial did not end")
	}
	if _, err = clients[1].Status(ctx, tokens[1]); err != nil {
		t.Fatal("other sidecar device was revoked", err)
	}
}
