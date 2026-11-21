package capture

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/ehzyil/connect-hub/internal/netpolicy"
	"github.com/ehzyil/connect-hub/internal/resolved"
	"github.com/ehzyil/connect-hub/internal/splitdns"
	"github.com/ehzyil/connect-hub/internal/workeripc"
)

// This uses the same helper control/launch APIs as the GUI. Only the remote
// tunnel is a fixture; DNS, system resolver, scopes and nftables are real.
func TestAliasServiceNamespace(t *testing.T) {
	if os.Getenv("ECH_ALIAS_WORKER") == "" || os.Getenv("ECH_RESOLVED_NAMESPACE") != "1" {
		t.Skip("run scripts/test-alias-linux.sh")
	}
	namespaceGuard(t)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	run := func(tool, input string, args ...string) string {
		t.Helper()
		b, err := systemCommand(ctx, tool, input, args...)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	run("ip", "", "link", "set", "lo", "up")
	run("ip", "", "link", "add", "aliasprobe", "type", "dummy")
	run("ip", "", "addr", "add", "198.18.0.2/24", "dev", "aliasprobe")
	run("ip", "", "link", "set", "aliasprobe", "up")
	run("ip", "", "link", "add", "aliasoldroute", "type", "dummy")
	run("ip", "", "addr", "add", "192.0.2.2/24", "dev", "aliasoldroute")
	run("ip", "", "link", "set", "aliasoldroute", "up")
	// Model a pre-existing broad route, as used by another TUN client. DNAT
	// must recalculate the real route without deleting this route or its mark.
	run("ip", "", "route", "add", "192.0.0.0/2", "dev", "aliasoldroute")
	baselineRoutes := run("ip", "", "-j", "-4", "route", "show", "table", "all")
	baselineRules := run("ip", "", "-j", "-4", "rule", "show")
	serveDirect := func() net.Listener {
		ln, err := net.Listen("tcp4", "198.18.0.2:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer c.Close()
					c.SetDeadline(time.Now().Add(time.Second))
					_, _ = c.Read(make([]byte, 32))
					source, _, _ := net.SplitHostPort(c.RemoteAddr().String())
					body := "original"
					if source != "198.18.0.2" {
						body = "wrong-source:" + source
					}
					_, _ = io.WriteString(c, body)
				}()
			}
		}()
		return ln
	}
	directA, directB := serveDirect(), serveDirect()
	portA, portB := directA.Addr().(*net.TCPAddr).Port, directB.Addr().(*net.TCPAddr).Port
	password := strings.Repeat("a", 64)
	worker := exec.CommandContext(ctx, os.Getenv("ECH_ALIAS_WORKER"), "-test.run=^TestAliasPlatformPeer$")
	worker.Env = append(os.Environ(), "ECH_ALIAS_PEER=1")
	wi, err := worker.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	wo, err := worker.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = worker.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		wi.Close()
		wo.Close()
		if err := worker.Wait(); err != nil {
			t.Error("worker fixture", err)
		}
	}()
	enc, dec := json.NewEncoder(wi), json.NewDecoder(wo)
	if err = enc.Encode(struct {
		Original     string
		PortA, PortB int
		Password     string
	}{"198.18.0.2", portA, portB, password}); err != nil {
		t.Fatal(err)
	}
	var ready workeripc.Message
	if err = dec.Decode(&ready); err != nil || ready.Version != workeripc.Version || ready.Type != "ready" {
		t.Fatal("worker ready", err)
	}

	dir := t.TempDir()
	serviceDir := filepath.Join(dir, "service")
	s, err := newService(os.Getuid(), serviceDir, systemCommand)
	if err != nil {
		t.Fatal(err)
	}
	serviceCtx, stopService := context.WithCancel(ctx)
	serviceDone := make(chan error, 1)
	go func() { serviceDone <- s.Serve(serviceCtx) }()
	stopped := false
	defer func() {
		if !stopped {
			stopService()
			<-serviceDone
			s.Close()
		}
	}()
	socket := filepath.Join(serviceDir, "control.sock")
	waitFor := func(fn func() bool) {
		t.Helper()
		deadline := time.Now().Add(12 * time.Second)
		for !fn() {
			if time.Now().After(deadline) {
				t.Fatal("lifecycle condition timed out")
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	waitFor(func() bool { _, err := os.Stat(socket); return err == nil })
	var lease *AliasLease
	gate := make(chan struct{})
	var dnsMu sync.Mutex
	var sequence int
	server, err := splitdns.Listen(ctx, func(ctx context.Context, packet []byte) ([]byte, error) {
		select {
		case <-gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		dnsMu.Lock()
		defer dnsMu.Unlock()
		sequence++
		if err := enc.Encode(workeripc.Message{Version: workeripc.Version, Session: "alias-fixture", Type: "dns_query", RequestID: strconv.Itoa(sequence), DNS: packet, CaptureDNS: true, CapturePrefix: lease.Prefix}); err != nil {
			return nil, err
		}
		var reply workeripc.Message
		if err := dec.Decode(&reply); err != nil {
			return nil, err
		}
		if reply.Error != "" {
			return nil, fmt.Errorf("worker: %s", reply.Error)
		}
		if err := lease.Publish(ctx, reply.DNSAliases); err != nil {
			return nil, err
		}
		return reply.DNS, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	dnsConfig := resolved.Config{Address: server.Addr(), Domains: []string{"corp.test"}}
	networks := []netpolicy.Range{{Min: "198.18.0.2", Max: "198.18.0.2"}}
	lease, err = prepareAliasLease(ctx, dnsConfig, networks, socket, uint32(os.Getuid()))
	close(gate)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	prefix := netip.MustParsePrefix(lease.Prefix)
	if prefix.Contains(netip.MustParseAddr("198.18.0.2")) {
		t.Fatal("prefix overlaps original destination")
	}
	target, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(dir, "target.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	t.Setenv("EASYCONNECT_HELPER_TARGET", target.Addr().String())
	exe, _ := os.Executable()
	// No real-IP guard grant: model names resolved dynamically with domain-only
	// resources, where only the synthetic range identifies unsupported UDP.
	upstream := Upstream{Address: ready.Address, Username: "test", Password: password, DNS: &dnsConfig, Alias: lease.Ref()}
	// Before any launch, an empty idle lease retires its kernel table but
	// reserves the pool. Reactivation must recheck intervening foreign routes.
	waitFor(func() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.aliases[lease.ID].dormant })
	run("ip", "", "route", "add", lease.Prefix, "dev", "aliasoldroute")
	if p, err := launch(ctx, Program{Executable: exe, Args: []string{"-test.run=^TestManagedProgram$"}}, upstream, socket, uint32(os.Getuid()), exe, []string{"-test.run=^TestManagedLaunchBarrier$"}); err == nil {
		p.Close()
		t.Fatal("reactivation ignored a newly conflicting route")
	}
	run("ip", "", "route", "del", lease.Prefix, "dev", "aliasoldroute")
	t.Log("idle pool has no kernel table; reactivation refuses a newly conflicting foreign route before releasing the program")
	type selected struct {
		process *Process
		conn    net.Conn
		enc     *json.Encoder
		dec     *json.Decoder
	}
	start := func() selected {
		t.Helper()
		p, err := launch(ctx, Program{Executable: exe, Args: []string{"-test.run=^TestManagedProgram$"}}, upstream, socket, uint32(os.Getuid()), exe, []string{"-test.run=^TestManagedLaunchBarrier$"})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { p.Close() })
		target.SetDeadline(time.Now().Add(2 * time.Second))
		conn, err := target.Accept()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		app := selected{p, conn, json.NewEncoder(conn), json.NewDecoder(conn)}
		var result probeReply
		if err := app.dec.Decode(&result); err != nil {
			t.Fatal(err)
		}
		return app
	}
	request := func(app selected, name string, port int, child bool) probeReply {
		t.Helper()
		app.conn.SetDeadline(time.Now().Add(4 * time.Second))
		// The default resolver exercises the real private systemd-resolved link.
		if err := app.enc.Encode(probeRequest{Target: net.JoinHostPort(name, strconv.Itoa(port)), Child: child, Network: "tcp4"}); err != nil {
			t.Fatal(err)
		}
		var reply probeReply
		if err := app.dec.Decode(&reply); err != nil {
			t.Fatal(err)
		}
		return reply
	}
	check := func(reply probeReply, want string) {
		t.Helper()
		if reply.Error != "" || reply.Body != want {
			t.Fatalf("got=%+v want=%s", reply, want)
		}
	}
	natural := start()
	check(request(natural, "a.corp.test", portA, false), "vpn:a.corp.test")
	natural.conn.Close()
	waitFor(func() bool {
		_, err := os.Stat("/sys/fs/cgroup/" + scopePath(os.Getuid(), natural.process.id))
		return os.IsNotExist(err)
	})
	if err := natural.process.Close(); err != nil {
		t.Fatal("natural application exit broke alias cleanup:", err)
	}
	t.Log("natural program exit and scope removal preserve alias ownership verification")
	one, two := start(), start()
	for _, app := range []selected{one, two} {
		check(request(app, "a.corp.test", portA, false), "vpn:a.corp.test")
		check(request(app, "b.corp.test", portB, true), "vpn:b.corp.test")
		if reply := request(app, "a.corp.test", portB, false); reply.Body != "" {
			t.Fatal("domain port rights broadened", reply)
		}
	}
	check(probeNetwork("tcp4", net.JoinHostPort("a.corp.test", strconv.Itoa(portB))), "original")
	t.Log("two GUI-style launches and children share real system DNS, preserving separate domain/port rights; unselected uses original source/interface")
	other, err := dialControl(ctx, socket, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = other.call(ctx, frame{Type: "alias_publish", ID: lease.ID}); err == nil {
		t.Fatal("another controller published DNS")
	}
	other.conn.Close()
	if err := one.process.Close(); err != nil {
		t.Fatal(err)
	}
	check(request(one, "a.corp.test", portA, false), "original")
	check(request(two, "a.corp.test", portA, true), "vpn:a.corp.test")
	t.Log("stopping one launch atomically revokes its selection and keeps the other launch online")
	q := new(dns.Msg).SetQuestion("a.corp.test.", dns.TypeA)
	answer, _, err := (&dns.Client{Net: "tcp", Timeout: time.Second}).Exchange(q, server.Addr())
	if err != nil || len(answer.Answer) != 1 {
		t.Fatal("mapped DNS", err)
	}
	fake := answer.Answer[0].(*dns.A).A.String()
	udp, err := net.ListenPacket("udp4", "198.18.0.2:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		buf := make([]byte, 32)
		for {
			_, peer, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = udp.WriteTo([]byte("original-udp"), peer)
		}
	}()
	_, udpPort, _ := net.SplitHostPort(udp.LocalAddr().String())
	if err := two.enc.Encode(probeRequest{Target: net.JoinHostPort(fake, udpPort), Network: "udp4"}); err != nil {
		t.Fatal(err)
	}
	var unsupported probeReply
	if err := two.dec.Decode(&unsupported); err != nil {
		t.Fatal(err)
	}
	if unsupported.Error == "" || unsupported.Body != "" {
		t.Fatal("selected unsupported alias UDP escaped", unsupported)
	}
	check(probeNetwork("udp4", net.JoinHostPort(fake, udpPort)), "original-udp")
	t.Log("selected alias UDP rejects before DNAT; unselected UDP retains original path")
	if err := two.process.Close(); err != nil {
		t.Fatal(err)
	}
	check(request(two, fake, portA, false), "original")
	// Query publication requires an attached launch, not just an idle lease.
	if err := lease.Publish(ctx, nil); err == nil {
		t.Fatal("idle lease published DNS")
	}
	// The lease remains alive on normal stop and reuses the worker's stable pool.
	three := start()
	check(request(three, "b.corp.test", portB, false), "vpn:b.corp.test")
	lease.Close()
	waitFor(func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		a := s.aliases[lease.ID]
		return a != nil && a.owner == "" && len(s.sessions) == 0
	})
	check(request(three, fake, portA, true), "original")
	t.Log("shared DNS controller EOF revokes active application leases while leaving programs and children running")
	check(probeNetwork("tcp4", net.JoinHostPort(fake, strconv.Itoa(portA))), "original")
	stopService()
	if err := <-serviceDone; err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	stopped = true
	recovered, err := newService(os.Getuid(), serviceDir, systemCommand)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	if len(recovered.sessions) != 0 || len(recovered.aliases) != 1 {
		t.Fatal("wrong recovery state")
	}
	if a := recovered.aliases[lease.ID]; a.owner != "" || len(a.route.Groups) != 0 {
		t.Fatal("recovery restored application selection")
	}
	check(probeNetwork("tcp4", net.JoinHostPort(fake, strconv.Itoa(portA))), "original")
	t.Log("last stop/GUI EOF retains cached original destinations; helper restart restores no VPN selection")
	drainCtx, drainCancel := context.WithTimeout(ctx, 75*time.Second)
	defer drainCancel()
	if err := recovered.DrainAliases(drainCtx); err != nil {
		t.Fatal(err)
	}
	if got := run("nft", "", "list", "ruleset"); strings.TrimSpace(got) != "" {
		t.Fatal("alias or capture state leaked")
	}
	if got := run("ip", "", "-j", "-4", "route", "show", "table", "all"); got != baselineRoutes {
		t.Fatal("foreign route changed")
	}
	if got := run("ip", "", "-j", "-4", "rule", "show"); got != baselineRules {
		t.Fatal("foreign rules changed")
	}
	t.Log("recovery drains TTL-bounded journals/tables and preserves pre-existing routes and rules")
}
