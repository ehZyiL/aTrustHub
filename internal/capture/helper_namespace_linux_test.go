package capture

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehzyil/connect-hub/internal/netpolicy"
	"github.com/ehzyil/connect-hub/internal/proxy"
	"github.com/ehzyil/connect-hub/internal/resolved"
	"github.com/ehzyil/connect-hub/internal/splitdns"
	"github.com/miekg/dns"
)

func TestManagedLaunchBarrier(t *testing.T) {
	if os.Getenv("EASYCONNECT_HELPER_NAMESPACE") != "1" && os.Getenv("EASYCONNECT_CAPTURE_HOST_TEST") != "1" {
		t.Skip("subprocess only")
	}
	// Test executable arguments select this function; protocol contains the
	// target program and arguments and remains identical to the desktop path.
	if err := RunLaunchBarrier(os.Stdin, os.Stdout); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func TestManagedProgram(t *testing.T) {
	path := os.Getenv("EASYCONNECT_HELPER_TARGET")
	if path == "" {
		t.Skip("subprocess only")
	}
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	id, err := identifyProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	enc, dec := json.NewEncoder(c), json.NewDecoder(c)
	_ = enc.Encode(probeReply{Group: id.Group})
	for {
		var req probeRequest
		if err := dec.Decode(&req); err == io.EOF {
			return
		} else if err != nil {
			t.Fatal(err)
		}
		var reply probeReply
		if req.Child {
			exe, _ := os.Executable()
			cmd := exec.Command(exe, "-test.run=^TestCaptureProbeChild$")
			cmd.Env = append(os.Environ(), "EASYCONNECT_CAPTURE_CHILD=1")
			b, _ := json.Marshal(req)
			cmd.Stdin = strings.NewReader(string(b))
			b, err = cmd.Output()
			if err != nil {
				reply.Error = err.Error()
			} else if err = json.Unmarshal([]byte(strings.SplitN(string(b), "\n", 2)[0]), &reply); err != nil {
				reply.Error = err.Error()
			}
		} else {
			reply = probeWithResolver(req.Network, req.Target, req.DNS)
		}
		_ = enc.Encode(reply)
	}
}

func namespaceGuard(t *testing.T) {
	t.Helper()
	if os.Getenv("EASYCONNECT_HELPER_NAMESPACE") != "1" {
		t.Skip("run scripts/test-capture-linux.sh")
	}
	self, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	if host := os.Getenv("EASYCONNECT_CAPTURE_HOST_NETNS"); host == "" || host == self {
		t.Fatal("refusing host network mutation")
	}
	ifaces, err := net.Interfaces()
	if err != nil || len(ifaces) != 1 || ifaces[0].Name != "lo" {
		t.Fatal("test requires an empty private network namespace")
	}
	if os.Geteuid() == 0 {
		t.Fatal("helper lifecycle test needs --map-current-user --keep-caps")
	}
	b, err := systemCommand(context.Background(), "nft", "", "list", "ruleset")
	if err != nil || strings.TrimSpace(string(b)) != "" {
		t.Fatal("test requires an empty nftables ruleset")
	}
}

func TestHelperNamespace(t *testing.T) {
	namespaceGuard(t)
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()
	run := func(input, tool string, args ...string) string {
		t.Helper()
		b, err := systemCommand(ctx, tool, input, args...)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	run("", "ip", "link", "set", "lo", "up")
	run("", "ip", "link", "add", "ecprobe", "type", "dummy")
	run("", "ip", "addr", "add", "198.18.0.1/24", "dev", "ecprobe")
	run("", "ip", "addr", "add", "198.18.0.2/32", "dev", "ecprobe")
	run("", "ip", "addr", "add", "198.18.0.4/32", "dev", "ecprobe")
	run("", "ip", "-6", "addr", "add", "fd00::2/128", "dev", "ecprobe", "nodad")
	run("", "ip", "-6", "addr", "add", "2001:db8::2/128", "dev", "ecprobe", "nodad")
	run("", "ip", "link", "set", "ecprobe", "up")
	// Representative pre-existing state must survive successful and failed
	// sessions. This is an isolation fixture, not a claim of host coexistence.
	run("table ip foreign {\n chain out {\n type route hook output priority -150; policy accept;\n ip daddr 203.0.113.250 meta mark set 0x40000000\n }\n}\n", "nft", "-f", "-")
	run("", "ip", "rule", "add", "pref", "5210", "fwmark", "0x80000/0xff0000", "lookup", "52")
	baselineNft := run("", "nft", "-j", "list", "ruleset")
	baselineRules := run("", "ip", "-j", "-4", "rule", "show")
	baselineRoutes := run("", "ip", "-j", "-4", "route", "show", "table", "all")
	// Link counters and IPv6 link-local lifetimes change independently. Check
	// ownership names instead of comparing the complete dynamic JSON dump.
	noDNSLeases := func() bool {
		b, err := systemCommand(ctx, "ip", "", "-j", "link", "show")
		if err != nil {
			return false
		}
		var links []struct {
			Name string `json:"ifname"`
		}
		if json.Unmarshal(b, &links) != nil {
			return false
		}
		for _, link := range links {
			if strings.HasPrefix(link.Name, "echd") {
				return false
			}
		}
		if os.Getenv("ECH_RESOLVED_NAMESPACE") == "1" {
			b, err = systemCommand(ctx, "busctl", "", "--system", "--json=short", "get-property", "org.freedesktop.resolve1", "/org/freedesktop/resolve1", "org.freedesktop.resolve1.Manager", "Domains")
			if err != nil || strings.Contains(string(b), "corp.test") {
				return false
			}
		}
		return true
	}
	unchanged := func() {
		t.Helper()
		if got := run("", "nft", "-j", "list", "ruleset"); got != baselineNft {
			t.Fatalf("foreign nftables changed: %s", got)
		}
		if got := run("", "ip", "-j", "-4", "rule", "show"); got != baselineRules {
			t.Fatalf("policy rules leaked: %s", got)
		}
		if got := run("", "ip", "-j", "-4", "route", "show", "table", "all"); got != baselineRoutes {
			t.Fatalf("routes leaked: %s", got)
		}
		deadline := time.Now().Add(time.Second)
		for !noDNSLeases() {
			if time.Now().After(deadline) {
				t.Fatal("owned DNS link or routing domain leaked")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	respond := func(ln net.Listener, body string) {
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
					_, _ = io.WriteString(c, body)
				}()
			}
		}()
	}
	direct, err := net.Listen("tcp4", "198.18.0.2:0")
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Close()
	respond(direct, "direct")
	loop, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer loop.Close()
	respond(loop, "loopback")
	internal6, err := net.Listen("tcp6", "[fd00::2]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer internal6.Close()
	respond(internal6, "direct6")
	public6, err := net.Listen("tcp6", "[2001:db8::2]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer public6.Close()
	respond(public6, "public6")
	udpService := func(address string) *net.UDPConn {
		t.Helper()
		addr, _ := net.ResolveUDPAddr("udp4", address)
		conn, err := net.ListenUDP("udp4", addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		go func() {
			buf := make([]byte, 1024)
			for {
				_, peer, err := conn.ReadFromUDP(buf)
				if err != nil {
					return
				}
				_, _ = conn.WriteToUDP([]byte("direct-udp"), peer)
			}
		}()
		return conn
	}
	internalUDP := udpService("198.18.0.2:0")
	publicUDP := udpService("198.18.0.4:0")
	var failUpstream atomic.Bool
	upstream := Upstream{Username: "hub", Password: strings.Repeat("a", 64)}
	upstream.Networks = []netpolicy.Range{{Min: "198.18.0.2", Max: "198.18.0.2"}, {Min: "fd00::2", Max: "fd00::2"}}
	targets := make(chan string, 32)
	socks := proxy.New(proxy.Options{Addr: "127.0.0.1:0", SOCKSOnly: true, Auth: &proxy.Auth{Username: upstream.Username, Credential: upstream.Password}, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		targets <- address
		if failUpstream.Load() {
			return nil, errors.New("tunnel unavailable")
		}
		a, b := net.Pipe()
		go func() {
			defer b.Close()
			b.SetDeadline(time.Now().Add(time.Second))
			_, _ = b.Read(make([]byte, 32))
			_, _ = io.WriteString(b, "captured")
		}()
		return a, nil
	}})
	if err := socks.Start(); err != nil {
		t.Fatal(err)
	}
	defer socks.Close()
	upstream.Address = socks.Addr().String()
	if os.Getenv("ECH_RESOLVED_NAMESPACE") == "1" {
		dnsServer, err := splitdns.Listen(ctx, func(_ context.Context, packet []byte) ([]byte, error) {
			q := new(dns.Msg)
			if err := q.Unpack(packet); err != nil {
				return nil, err
			}
			m := new(dns.Msg).SetReply(q)
			if q.Question[0].Qtype == dns.TypeA {
				m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}, A: net.ParseIP("198.18.0.2")}}
			}
			return m.Pack()
		})
		if err != nil {
			t.Fatal(err)
		}
		defer dnsServer.Close()
		upstream.DNS = &resolved.Config{Address: dnsServer.Addr(), Domains: []string{"corp.test"}}
	}
	dir, err := os.MkdirTemp("", "ec-helper-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	serviceDir := filepath.Join(dir, "service")
	var failInstall atomic.Bool
	commands := func(ctx context.Context, tool, input string, args ...string) ([]byte, error) {
		if tool == "nft" && strings.Join(args, " ") == "-f -" && strings.Contains(input, "create table") && failInstall.CompareAndSwap(true, false) {
			return nil, errors.New("simulated nft install failure")
		}
		return systemCommand(ctx, tool, input, args...)
	}
	s, err := newService(os.Getuid(), serviceDir, commands)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	serviceCtx, stopService := context.WithCancel(ctx)
	defer stopService()
	serviceDone := make(chan error, 1)
	go func() { serviceDone <- s.Serve(serviceCtx) }()
	socket := filepath.Join(serviceDir, "control.sock")
	waitFor := func(fn func() bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if fn() {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("condition timed out")
	}
	waitFor(func() bool { _, err := os.Stat(socket); return err == nil })
	targetSocket := filepath.Join(dir, "target.sock")
	t.Setenv("EASYCONNECT_HELPER_TARGET", targetSocket)
	targetListener, err := net.ListenUnix("unix", &net.UnixAddr{Name: targetSocket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer targetListener.Close()
	exe, _ := os.Executable()
	program := Program{Executable: exe, Args: []string{"-test.run=^TestManagedProgram$"}}
	start := func() (*Process, error) {
		return launch(ctx, program, upstream, socket, uint32(os.Geteuid()), exe, []string{"-test.run=^TestManagedLaunchBarrier$"})
	}
	failInstall.Store(true)
	if p, err := start(); err == nil {
		p.Close()
		t.Fatal("program launched despite failed rule installation")
	} else if !strings.Contains(err.Error(), "simulated nft install failure") {
		t.Fatalf("launch failed before the intended rollback check: %v", err)
	}
	targetListener.SetDeadline(time.Now().Add(100 * time.Millisecond))
	if c, err := targetListener.Accept(); err == nil {
		c.Close()
		t.Fatal("target executed before successful attach")
	}
	targetListener.SetDeadline(time.Time{})
	unchanged()
	t.Log("failed nft install: target never runs; routes and journal rolled back")
	p, err := start()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	targetListener.SetDeadline(time.Now().Add(3 * time.Second))
	c, err := targetListener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	dec, enc := json.NewDecoder(c), json.NewEncoder(c)
	var ready probeReply
	if err := dec.Decode(&ready); err != nil {
		t.Fatal(err)
	}
	if ready.Group != scopePath(os.Getuid(), p.id) {
		t.Fatalf("wrong launch scope: %s", ready.Group)
	}
	requestNetwork := func(target string, child bool, network string) probeReply {
		t.Helper()
		if err := enc.Encode(probeRequest{Target: target, Child: child, Network: network}); err != nil {
			t.Fatal(err)
		}
		var res probeReply
		if err := dec.Decode(&res); err != nil {
			t.Fatal(err)
		}
		return res
	}
	request := func(target string, child bool) probeReply { return requestNetwork(target, child, "tcp4") }
	check := func(res probeReply, want string) {
		t.Helper()
		if res.Error != "" || res.Body != want {
			t.Fatalf("response=%+v want=%s", res, want)
		}
	}
	check(request(direct.Addr().String(), false), "captured")
	if got := <-targets; got != direct.Addr().String() {
		t.Fatal("original target lost")
	}
	check(request(direct.Addr().String(), true), "captured")
	<-targets
	check(probeGet(direct.Addr().String()), "direct")
	check(request(loop.Addr().String(), false), "loopback")
	for _, child := range []bool{false, true} {
		for _, target := range []struct{ network, address string }{{"udp4", internalUDP.LocalAddr().String()}, {"tcp6", internal6.Addr().String()}} {
			if got := requestNetwork(target.address, child, target.network); got.Error == "" || got.Body != "" {
				t.Fatalf("unsupported internal protocol escaped: %+v", got)
			}
		}
		check(requestNetwork(publicUDP.LocalAddr().String(), child, "udp4"), "direct-udp")
		check(requestNetwork(public6.Addr().String(), child, "tcp6"), "public6")
	}
	check(probeNetwork("udp4", internalUDP.LocalAddr().String()), "direct-udp")
	check(probeNetwork("tcp6", internal6.Addr().String()), "direct6")
	t.Log("internal UDP/IPv6 rejected for selected process and children; public and unselected paths preserved")
	_, port, _ := net.SplitHostPort(direct.Addr().String())
	if upstream.DNS != nil {
		check(request(net.JoinHostPort("first.corp.test", port), false), "captured")
		<-targets
		check(request(net.JoinHostPort("child.corp.test", port), true), "captured")
		<-targets
		check(probeGet(net.JoinHostPort("unselected.corp.test", port)), "direct")
		t.Log("system DNS -> session DNS -> selected program/child capture; unselected program still uses original path")
	}
	check(request(net.JoinHostPort("198.18.0.3", port), false), "captured")
	<-targets
	t.Log("launch barrier + UID + cgroup + authenticated SOCKS: process and child captured; others and loopback unchanged")
	parallel, err := start()
	if err != nil {
		t.Fatal(err)
	}
	targetListener.SetDeadline(time.Now().Add(3 * time.Second))
	parallelConn, err := targetListener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	parallelConn.SetDeadline(time.Now().Add(3 * time.Second))
	parallelDecoder, parallelEncoder := json.NewDecoder(parallelConn), json.NewEncoder(parallelConn)
	if err := parallelDecoder.Decode(&ready); err != nil {
		t.Fatal(err)
	}
	if err := parallelEncoder.Encode(probeRequest{Target: direct.Addr().String()}); err != nil {
		t.Fatal(err)
	}
	var secondReply probeReply
	if err := parallelDecoder.Decode(&secondReply); err != nil {
		t.Fatal(err)
	}
	check(secondReply, "captured")
	<-targets
	if err := parallel.Close(); err != nil {
		t.Fatal(err)
	}
	parallelConn.Close()
	if upstream.DNS != nil {
		check(request(net.JoinHostPort("shared.corp.test", port), false), "captured")
		<-targets
		t.Log("stopping one scope retains shared DNS for the remaining program")
	}
	check(request(direct.Addr().String(), false), "captured")
	<-targets
	t.Log("two active launch groups: independent marks, routes and cleanup")
	failUpstream.Store(true)
	if got := request(direct.Addr().String(), false); got.Body != "" {
		t.Fatalf("unexpected direct fallback: %+v", got)
	}
	<-targets
	failUpstream.Store(false)
	// Another authenticated connection cannot detach this controller's lease.
	other, err := dialControl(ctx, socket, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.call(ctx, frame{Type: "detach", ID: p.id}); err == nil {
		t.Fatal("other controller detached session")
	}
	other.conn.Close()
	// Preserve a crash journal for the same still-live scope, after normal detach.
	s.mu.Lock()
	lease := s.sessions[p.id].lease
	s.mu.Unlock()
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	unchanged()
	check(request(direct.Addr().String(), false), "direct")
	check(requestNetwork(internalUDP.LocalAddr().String(), false, "udp4"), "direct-udp")
	check(requestNetwork(internal6.Addr().String(), false, "tcp6"), "direct6")
	t.Log("detach: software remains alive; exactly owned rules removed")
	if err := saveJournal(filepath.Join(serviceDir, "journal"), lease); err != nil {
		t.Fatal(err)
	}
	if err := installRules(ctx, systemCommand, lease); err != nil {
		t.Fatal(err)
	}
	if lease.DNS != nil {
		if err := resolved.Install(ctx, resolved.Command(systemCommand), *lease.DNS); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	unchanged()
	t.Log("crash journal recovery: only the interrupted transaction's rules removed")
	_ = c.Close()
	// Closing the control socket models a GUI crash, independently of Close.
	p2, err := start()
	if err != nil {
		t.Fatal(err)
	}
	defer p2.Close()
	targetListener.SetDeadline(time.Now().Add(3 * time.Second))
	c2, err := targetListener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	p2.client.conn.Close()
	waitFor(func() bool { s.mu.Lock(); defer s.mu.Unlock(); return len(s.sessions) == 0 })
	unchanged()
	if _, err := identifyProcess(p2.PID); err != nil {
		t.Fatal("GUI crash killed target")
	}
	t.Log("GUI control EOF: owned network state cleaned; target process survives")
	_ = c2.Close()
	p3, err := start()
	if err != nil {
		t.Fatal(err)
	}
	defer p3.Close()
	targetListener.SetDeadline(time.Now().Add(3 * time.Second))
	c3, err := targetListener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c3.Close()
	run("", "nft", "flush", "table", "ip", "ech_"+p3.id)
	if _, err := p3.client.call(ctx, frame{Type: "ping", ID: p3.id}); err == nil {
		t.Fatal("empty capture table reported healthy")
	}
	waitFor(func() bool { s.mu.Lock(); defer s.mu.Unlock(); return len(s.sessions) == 0 })
	unchanged()
	t.Log("external rule loss: incomplete table detected, capture marked failed and owned routes cleaned")
	_ = c3.Close()
	p4, err := start()
	if err != nil {
		t.Fatal(err)
	}
	defer p4.Close()
	targetListener.SetDeadline(time.Now().Add(3 * time.Second))
	c4, err := targetListener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c4.Close()
	run("", "nft", "flush", "set", "inet", "echg_"+p4.id, "internal4")
	if _, err := p4.client.call(ctx, frame{Type: "ping", ID: p4.id}); err == nil {
		t.Fatal("empty guard set reported healthy")
	}
	waitFor(func() bool { s.mu.Lock(); defer s.mu.Unlock(); return len(s.sessions) == 0 })
	unchanged()
	t.Log("guard set loss: changed internal UDP policy detected and complete transaction cleaned")
	stopService()
	if err := <-serviceDone; err != nil {
		t.Fatal(err)
	}
}

func TestBarrierEOFDoesNotExecuteTarget(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("normal-user launch test")
	}
	var input strings.Builder
	p := Program{Executable: "/usr/bin/false"}
	if err := writeFrame(&input, launchMessage{Program: &p}); err != nil {
		t.Fatal(err)
	}
	var output strings.Builder
	if err := RunLaunchBarrier(strings.NewReader(input.String()), &output); !errors.Is(err, io.EOF) {
		t.Fatalf("err=%v", err)
	}
	r := bufio.NewReaderSize(strings.NewReader(output.String()), maxFrame)
	var ready launchMessage
	if err := readFrame(r, &ready); err != nil || ready.PID != os.Getpid() {
		t.Fatalf("no barrier response: %+v %v", ready, err)
	}
}
