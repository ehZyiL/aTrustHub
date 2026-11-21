package capture

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/ehzyil/connect-hub/internal/proxy"
	"github.com/ehzyil/connect-hub/internal/resolved"
	"github.com/ehzyil/connect-hub/internal/splitdns"
	"github.com/ehzyil/connect-hub/internal/workeripc"
)

// This opt-in test uses the installed system helper, never sudo. Only its own
// launch groups are captured. Both original and SOCKS destinations are local
// fixtures; it neither logs in to a VPN nor calls any external business service.
func TestCaptureHostLifecycle(t *testing.T) {
	if os.Getenv("EASYCONNECT_CAPTURE_HOST_TEST") != "1" {
		t.Skip("opt in with scripts/test-capture-host-linux.sh LOCAL_IPV4")
	}
	for _, mode := range []string{"tcp", "dns_alias", "dns_alias_exit"} {
		t.Run(mode, func(t *testing.T) { captureHostLifecycle(t, mode != "tcp", mode == "dns_alias_exit") })
	}
}

func captureHostLifecycle(t *testing.T, withDNS, naturalExit bool) {
	if os.Geteuid() == 0 {
		t.Fatal("run as the ordinary desktop user with the helper already installed")
	}
	ip := net.ParseIP(os.Getenv("EASYCONNECT_CAPTURE_HOST_ADDRESS"))
	if ip == nil || ip.To4() == nil || !ip.IsGlobalUnicast() || ip.IsLoopback() {
		t.Fatal("specify a local non-loopback IPv4 address")
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	local := false
	for _, addr := range addresses {
		if subnet, ok := addr.(*net.IPNet); ok && subnet.IP.Equal(ip) {
			local = true
		}
	}
	if !local {
		t.Fatal("refusing to use an address not assigned to this host")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	if err := HelperAvailable(ctx); err != nil {
		t.Fatal(err)
	}
	helperPID := func() int32 {
		t.Helper()
		client, err := dialControl(ctx, SocketPath(os.Getuid()), 0)
		if err != nil {
			t.Fatal(err)
		}
		defer client.conn.Close()
		peer, err := peerCredentials(client.conn)
		if err != nil {
			t.Fatal(err)
		}
		return peer.Pid
	}
	pid := helperPID()
	defer func() {
		if helperPID() != pid {
			t.Error("system helper restarted during the test")
		}
	}()
	t.Log("root helper identity and protocol handshake passed")
	readState := func() []string {
		t.Helper()
		var state []string
		for _, args := range [][]string{{"-j", "-N", "-4", "rule", "show"}, {"-j", "-N", "-4", "route", "show", "table", "all"}} {
			b, err := systemCommand(ctx, "ip", "", args...)
			if err != nil {
				t.Fatal(err)
			}
			var rows []map[string]any
			if err := json.Unmarshal(b, &rows); err != nil {
				t.Fatal(err)
			}
			for _, row := range rows {
				delete(row, "expires")
				delete(row, "cache")
				b, _ := json.Marshal(row)
				state = append(state, string(b))
			}
		}
		if withDNS {
			b, err := systemCommand(ctx, "busctl", "", "--system", "--json=short", "get-property", "org.freedesktop.resolve1", "/org/freedesktop/resolve1", "org.freedesktop.resolve1.Manager", "Domains")
			if err != nil {
				t.Fatal(err)
			}
			state = append(state, string(b))
		}
		sort.Strings(state)
		return state
	}
	baseline := strings.Join(readState(), "\n")
	defer func() {
		if strings.Join(readState(), "\n") != baseline {
			t.Error("host IPv4 routes/rules differ after the test; inspect concurrent network changes and helper recovery")
		}
	}()
	listen := func(address, reply string) net.Listener {
		t.Helper()
		ln, err := net.Listen("tcp4", address)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer c.Close()
					_ = c.SetDeadline(time.Now().Add(2 * time.Second))
					_, _ = c.Read(make([]byte, 32))
					_, _ = io.WriteString(c, reply)
				}()
			}
		}()
		return ln
	}
	direct := listen(net.JoinHostPort(ip.String(), "0"), "direct")
	loop := listen("127.0.0.1:0", "loopback")
	upstream := Upstream{Username: "host-fixture", Password: randomID() + randomID()}
	requestTarget, fixtureTarget := direct.Addr().String(), direct.Addr().String()
	var aliases *AliasLease
	if withDNS {
		domain := "ech-smoke-" + randomID() + ".test"
		var current atomic.Pointer[AliasLease]
		server, err := splitdns.Listen(ctx, func(ctx context.Context, packet []byte) ([]byte, error) {
			q := new(dns.Msg)
			if err := q.Unpack(packet); err != nil {
				return nil, err
			}
			m := new(dns.Msg).SetReply(q)
			if len(q.Question) != 1 || q.Question[0].Name != domain+"." {
				m.Rcode = dns.RcodeNameError
				return m.Pack()
			}
			if q.Question[0].Qtype == dns.TypeA {
				lease := current.Load()
				if lease == nil {
					return nil, fmt.Errorf("fixture alias is not ready")
				}
				address := netip.MustParsePrefix(lease.Prefix).Addr().Next().String()
				if err := lease.Publish(ctx, []workeripc.DNSAlias{{Address: address, Original: ip.String(), TTL: 5}}); err != nil {
					return nil, err
				}
				m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: domain + ".", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3}, A: net.ParseIP(address)}}
			}
			return m.Pack()
		})
		if err != nil {
			t.Fatal(err)
		}
		defer server.Close()
		upstream.DNS = &resolved.Config{Address: server.Addr(), Domains: []string{domain}}
		aliases, err = PrepareAliases(ctx, *upstream.DNS, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer aliases.Close()
		current.Store(aliases)
		upstream.Alias = aliases.Ref()
		_, port, _ := net.SplitHostPort(requestTarget)
		requestTarget = net.JoinHostPort(domain, port)
		fixtureTarget = net.JoinHostPort(netip.MustParsePrefix(aliases.Prefix).Addr().Next().String(), port)
	}
	socks := proxy.New(proxy.Options{Addr: "127.0.0.1:0", SOCKSOnly: true, Auth: &proxy.Auth{Username: upstream.Username, Credential: upstream.Password}, Dial: func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" && network != "tcp4" || address != fixtureTarget {
			return nil, fmt.Errorf("fixture refuses a nonlocal or unexpected target")
		}
		a, b := net.Pipe()
		go func() {
			defer b.Close()
			_ = b.SetDeadline(time.Now().Add(2 * time.Second))
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
	targetSocket := filepath.Join(t.TempDir(), "target.sock")
	t.Setenv("EASYCONNECT_HELPER_TARGET", targetSocket)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: targetSocket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	program := Program{Executable: exe, Args: []string{"-test.run=^TestManagedProgram$"}}
	p, err := launch(ctx, program, upstream, SocketPath(os.Getuid()), 0, exe, []string{"-test.run=^TestManagedLaunchBarrier$"})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	_ = ln.SetDeadline(time.Now().Add(3 * time.Second))
	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	dec, enc := json.NewDecoder(c), json.NewEncoder(c)
	var ready probeReply
	if err := dec.Decode(&ready); err != nil || ready.Group != scopePath(os.Getuid(), p.id) {
		t.Fatalf("program did not enter the managed scope: %v", err)
	}
	request := func(address string, child bool) probeReply {
		t.Helper()
		if err := enc.Encode(probeRequest{Target: address, Child: child, Network: "tcp4"}); err != nil {
			t.Fatal(err)
		}
		var res probeReply
		if err := dec.Decode(&res); err != nil {
			t.Fatal(err)
		}
		return res
	}
	check := func(res probeReply, want string) {
		t.Helper()
		if res.Error != "" || res.Body != want {
			t.Fatalf("local fixture response: %+v, want %q", res, want)
		}
	}
	check(request(requestTarget, false), "captured")
	check(request(requestTarget, true), "captured")
	check(probeGet(requestTarget), "direct")
	check(request(loop.Addr().String(), false), "loopback")
	t.Log("selected program and new child captured; unselected program and loopback preserved")
	res, err := p.client.call(ctx, frame{Type: "ping", ID: p.id})
	if err != nil || !res.Active {
		t.Fatalf("installed rule verification failed: %v", err)
	}
	if withDNS {
		q := new(dns.Msg).SetQuestion(upstream.DNS.Domains[0]+".", dns.TypeA)
		for _, transport := range []string{"udp", "tcp"} {
			reply, _, err := (&dns.Client{Net: transport, Timeout: 2 * time.Second}).ExchangeContext(ctx, q, "127.0.0.53:53")
			if err != nil || reply == nil || reply.Rcode != dns.RcodeSuccess || len(reply.Answer) == 0 {
				t.Fatalf("host resolved %s query failed: %v", transport, err)
			}
		}
		t.Log("host resolved UDP/TCP, synthetic domain identity and unselected destination restoration passed")
	}
	if naturalExit {
		_ = c.Close()
		deadline := time.Now().Add(5 * time.Second)
		for {
			_, err := os.Stat("/sys/fs/cgroup/" + scopePath(os.Getuid(), p.id))
			if os.IsNotExist(err) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("fixture's scope was not collected after natural exit")
			}
			time.Sleep(20 * time.Millisecond)
		}
		if err := p.Close(); err != nil {
			t.Fatal("natural application exit broke host cleanup:", err)
		}
		t.Log("natural exit and collected scope cleaned without helper failure")
		return
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	check(request(fixtureTarget, false), "direct")
	check(request(fixtureTarget, true), "direct")
	t.Log("detach verified: original process and new child remain alive with the original route")
}
