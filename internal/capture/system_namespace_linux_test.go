package capture

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qy/easyconnect/internal/netpolicy"
	"github.com/qy/easyconnect/internal/proxy"
)

func TestSystemHelperTCPAndRecoveryInNamespace(t *testing.T) {
	requireSystemNamespace(t)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	command := func(args ...string) string {
		t.Helper()
		out, err := systemCommand(ctx, "ip", "", args...)
		if err != nil {
			t.Fatal(args, err)
		}
		return string(out)
	}
	command("link", "set", "lo", "up")
	command("link", "add", "echtest", "type", "dummy")
	command("addr", "add", "192.0.2.1/24", "dev", "echtest")
	command("link", "set", "echtest", "up")
	rulesBefore := command("-j", "-N", "-4", "rule", "show")
	routesBefore := command("-j", "-N", "-4", "route", "show", "table", "all")

	var bOffline atomic.Bool
	a := netpolicy.Range{Min: "192.0.2.40", Max: "192.0.2.40"}
	b := netpolicy.Range{Min: "192.0.2.41", Max: "192.0.2.41"}
	secret := strings.Repeat("a", 64)
	socks := proxy.New(proxy.Options{Addr: "127.0.0.1:0", Context: ctx, SOCKSOnly: true,
		Auth: &proxy.Auth{Username: "system", Credential: secret},
		Dial: func(_ context.Context, _, address string) (net.Conn, error) {
			switch address {
			case a.Min + ":443":
			case b.Min + ":443":
				if bOffline.Load() {
					return nil, fmt.Errorf("gateway B is offline")
				}
			default:
				return nil, fmt.Errorf("unexpected capture target: %s", address)
			}
			client, peer := net.Pipe()
			go func() { defer peer.Close(); _, _ = io.WriteString(peer, address) }()
			return client, nil
		}})
	if err := socks.Start(); err != nil {
		t.Fatal(err)
	}
	defer socks.Close()
	s, err := newService(1000, filepath.Join(t.TempDir(), "capture"), systemCommand)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// The test client uses the namespace's root UID. Production constructors
	// still require a non-root authorized UID for the GUI.
	s.uid = os.Getuid()
	path := filepath.Join(s.dir, "control.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			go s.handle(ctx, conn)
		}
	}()
	client, err := dialControl(ctx, path, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer client.conn.Close()
	lease := &SystemLease{client: client, path: path}
	config := SystemConfig{Upstream: Upstream{Address: socks.Addr().String(), Username: "system", Password: secret},
		Resources: []SystemResource{
			{ID: strings.Repeat("a", 32), Gateway: "203.0.113.1", Networks: []netpolicy.Range{a}},
			{ID: strings.Repeat("b", 32), Gateway: "203.0.113.2", Networks: []netpolicy.Range{b}},
		}}
	mode, err := s.lockCaptureMode(false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = lease.Start(ctx, config)
	mode()
	if err == nil || command("-j", "-N", "-4", "rule", "show") != rulesBefore {
		t.Fatal("system mode modified routes while software mode held the lock", err)
	}
	bad := config
	bad.Resources = append([]SystemResource(nil), config.Resources...)
	bad.Resources[0].Gateway = a.Min
	if _, err := lease.Start(ctx, bad); err == nil || command("-j", "-N", "-4", "rule", "show") != rulesBefore {
		t.Fatal("capture of a VPN gateway was accepted or left a rule", err)
	}
	if _, err := lease.Start(ctx, config); err != nil {
		t.Fatal(err)
	}
	if mode, err := s.lockCaptureMode(false); err == nil {
		mode()
		t.Fatal("software mode could enter during system mode")
	}
	if err := lease.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	if got := command("-4", "route", "get", "192.0.2.99"); !strings.Contains(got, "dev echtest") {
		t.Fatal("unowned target changed route", got)
	}
	checkTCP := func(ip string, available bool) {
		t.Helper()
		address := ip + ":443"
		conn, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp4", address)
		if err == nil {
			defer conn.Close()
			_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			data := make([]byte, len(address))
			_, err = io.ReadFull(conn, data)
			if err == nil && string(data) != address {
				t.Fatalf("resource %s reached wrong destination %q", address, data)
			}
		}
		if (err == nil) != available {
			t.Fatalf("resource %s, available %t: %v", address, available, err)
		}
	}
	checkTCP(a.Min, true)
	checkTCP(b.Min, true)
	bOffline.Store(true)
	config.Resources[1].Guard = true
	if _, err := lease.Sync(ctx, config); err != nil {
		t.Fatal(err)
	}
	checkTCP(a.Min, true)
	checkTCP(b.Min, false)
	bOffline.Store(false)
	config.Resources[1].Guard = false
	config.Resources[1].ID = strings.Repeat("c", 32)
	if _, err := lease.Sync(ctx, config); err != nil {
		t.Fatal(err)
	}
	checkTCP(b.Min, true)

	// Losing the controller must release all routes and let the same GUI
	// confirm cleanup over a fresh authenticated connection.
	_ = client.conn.Close()
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if command("-j", "-N", "-4", "rule", "show") != rulesBefore || command("-j", "-N", "-4", "route", "show", "table", "all") != routesBefore {
		t.Fatal("system capture changed the baseline after cleanup")
	}
}

func TestSystemHelperProcessCrashRecoveryInNamespace(t *testing.T) {
	requireSystemNamespace(t)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	if dir := os.Getenv("EASYCONNECT_SYSTEM_TUN_CRASH_CHILD"); dir != "" {
		s, err := newService(1000, dir, systemCommand)
		if err != nil {
			t.Fatal(err)
		}
		config := SystemConfig{Upstream: Upstream{Address: "127.0.0.1:12345", Username: "system", Password: strings.Repeat("a", 64)}, Resources: []SystemResource{
			{ID: strings.Repeat("a", 32), Gateway: "203.0.113.1", Networks: []netpolicy.Range{{Min: "192.0.2.43", Max: "192.0.2.43"}}},
		}}
		if _, err := s.systemControl(ctx, "child", frame{Type: "system_start", System: &config}); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "ready"), nil, 0600); err != nil {
			t.Fatal(err)
		}
		<-ctx.Done()
		t.Fatal("crash fixture was not terminated")
	}
	state := func(table ...string) string {
		t.Helper()
		out, err := systemCommand(ctx, "ip", "", table...)
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	}
	ruleArgs := []string{"-j", "-N", "-4", "rule", "show"}
	routeArgs := []string{"-j", "-N", "-4", "route", "show", "table", "all"}
	beforeRules, beforeRoutes := state(ruleArgs...), state(routeArgs...)
	dir := filepath.Join(t.TempDir(), "capture")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestSystemHelperProcessCrashRecoveryInNamespace$")
	cmd.Env = append(os.Environ(), "EASYCONNECT_SYSTEM_TUN_CRASH_CHILD="+dir)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	for {
		if _, err := os.Stat(filepath.Join(dir, "ready")); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("crash fixture did not install routes", ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	if state(ruleArgs...) == beforeRules || state(routeArgs...) == beforeRoutes {
		t.Fatal("fixture did not change network state")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	if state(ruleArgs...) == beforeRules || state(routeArgs...) != beforeRoutes {
		t.Fatal("process crash did not release its nonpersistent interface and routes")
	}
	s, err := newService(1000, dir, systemCommand)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if state(ruleArgs...) != beforeRules || state(routeArgs...) != beforeRoutes {
		t.Fatal("helper recovery did not restore the network baseline")
	}
}

func TestSystemRestartGuardsCachedDNSUntilTTLExpires(t *testing.T) {
	requireSystemNamespace(t)
	if _, err := systemCommand(context.Background(), "ip", "", "link", "set", "lo", "up"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	s, err := newService(1000, filepath.Join(t.TempDir(), "capture"), systemCommand)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	routesBefore, err := snapshot(ctx, systemCommand)
	if err != nil {
		t.Fatal(err)
	}
	allocation, err := allocateRouting(routesBefore)
	if err != nil {
		t.Fatal(err)
	}
	routes := systemRoutes{routingAllocation: allocation, ID: strings.Repeat("f", 32), Source: netip.MustParseAddr("198.18.42.1")}
	now, err := bootNow()
	if err != nil {
		t.Fatal(err)
	}
	retired := netip.MustParsePrefix("198.19.32.0/20")
	if err := (systemJournal{Routes: routes, Pools: map[string]int64{retired.String(): now + int64(2*time.Second)}}).save(s.systemJournalPath()); err != nil {
		t.Fatal(err)
	}
	config := SystemConfig{Upstream: Upstream{Address: "127.0.0.1:12345", Username: "system", Password: strings.Repeat("a", 64)},
		Resources: []SystemResource{{ID: strings.Repeat("a", 32), Gateway: "203.0.113.1", Networks: []netpolicy.Range{{Min: "192.0.2.40", Max: "192.0.2.40"}}}}}
	if _, err := s.systemControl(ctx, "restart-owner", frame{Type: "system_start", System: &config}); err != nil {
		t.Fatal(err)
	}
	if !s.system.routes[retired] {
		t.Fatal("old synthetic pool lost its rejecting guard after restart", s.system.routes, s.system.journal.Pools)
	}
	if _, err := s.system.acquireTarget(netip.MustParseAddr("198.19.32.1")); err == nil {
		t.Fatal("old synthetic DNS mapping was restored as an authorization")
	}
	s.system.journal.Pools[retired.String()] = now - 1
	if err := s.system.prune(ctx); err != nil {
		t.Fatal(err)
	}
	if s.system.routes[retired] {
		t.Fatal("expired retired pool route was not released")
	}
}
