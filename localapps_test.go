package main

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/ehzyil/connect-hub/internal/localapps"
	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/ehzyil/connect-hub/internal/store"
	"github.com/ehzyil/connect-hub/internal/vpn"
)

type localAppSession struct {
	dial func(context.Context, string, string) (net.Conn, error)
}

func (s localAppSession) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	return s.dial(ctx, network, address)
}
func (localAppSession) Info() vpn.SessionInfo { return vpn.SessionInfo{ClientIP: "10.0.0.1"} }
func (localAppSession) Close() error          { return nil }

func TestLocalAppSavedAndGatewayDisconnectStopsForward(t *testing.T) {
	a := testApp(t)
	a.mgr.Close()
	backend, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		c, err := backend.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.WriteString(c, "database-ready")
	}()
	pointPort, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := pointPort.Addr().(*net.TCPAddr).Port
	_ = pointPort.Close()
	a.mgr = vpn.NewManager(func(context.Context, model.AccessPoint, vpn.Credentials) (vpn.Session, error) {
		return localAppSession{dial: (&net.Dialer{}).DialContext}, nil
	}, func(string) (vpn.Credentials, error) { return vpn.Credentials{Login: "test-only-password"}, nil }, a.bus, nil)
	t.Cleanup(a.mgr.Close)
	a.local = localapps.NewManager(nil)
	t.Cleanup(func() { _ = a.local.Close() })
	_, err = a.store.Update(func(cfg *model.Config) error {
		cfg.Settings.AggregateEnabled = false
		cfg.Settings.AutoReconnect = false
		cfg.Settings.HealthIntervalSec = 0
		cfg.Points = []model.AccessPoint{{ID: "point", Name: "gateway", Server: "gateway.example", Port: 443, Username: "user", Protocol: model.ProtocolEasyConnect, AuthMode: string(model.AuthModePassword), SocksPort: port}}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.saveConfig(); err != nil {
		t.Fatal(err)
	}
	a.localEditor = localAppDraft{open: true, name: "db", mode: localModeLabel(model.LocalAppTCPForward), point: a.pointChoice(a.cfg.Points[0]), remote: backend.Addr().String(), port: "0"}
	a.saveLocalApp()
	if a.localEditor.open {
		t.Fatalf("save failed: %s", a.localEditor.err)
	}
	id := a.cfg.LocalApps[0].ID
	loaded, err := store.Open(a.dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Config().LocalApps) != 1 {
		t.Fatal("local app was not persisted")
	}
	if _, err := a.localProxyFor("point"); err == nil {
		t.Fatal("offline point accepted")
	}
	a.mgr.Connect("point")
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		v, _ := a.mgr.View("point")
		if v.State == vpn.StateOnline {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	a.startLocalApp(id)
	v := a.local.View(id)
	if !v.Running {
		t.Fatalf("start failed: %s", a.toast)
	}
	c, err := net.DialTimeout("tcp4", v.LocalAddress, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	body, err := io.ReadAll(c)
	_ = c.Close()
	if err != nil || string(body) != "database-ready" {
		t.Fatalf("forward result=%q %v", body, err)
	}
	a.removePoint("point")
	if a.cfg.Find("point") == nil {
		t.Fatal("point with local-app reference deleted")
	}
	a.mgr.Disconnect("point")
	a.reconcileLocalApps()
	if a.local.View(id).Running {
		t.Fatal("forward remained running after VPN disconnect")
	}
	if c, err := net.DialTimeout("tcp4", v.LocalAddress, 100*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("forward listener leaked")
	}
}
