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
	"github.com/ehzyil/connect-hub/internal/splitdns"
	"github.com/ehzyil/connect-hub/internal/workeripc"
)

// This proof spans both reference modules and the actual kernel. It exercises
// the proposed alias path, not a claim that helper retirement is integrated.
func TestAliasNamespace(t *testing.T) {
	if os.Getenv("ECH_ALIAS_WORKER") == "" {
		t.Skip("run scripts/test-alias-linux.sh")
	}
	namespaceGuard(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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
	state, err := snapshot(ctx, systemCommand)
	if err != nil {
		t.Fatal(err)
	}
	prefix, err := chooseAliasPrefix(state, []netpolicy.Range{{Min: "198.18.0.2", Max: "198.18.0.2"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	base := netip.MustParsePrefix(prefix).Addr().As4()
	end := netip.AddrFrom4([4]byte{base[0], base[1], base[2] + 15, 255})
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
	s, err := newService(os.Getuid(), filepath.Join(dir, "service"), systemCommand)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	serviceCtx, stopService := context.WithCancel(ctx)
	defer stopService()
	serviceDone := make(chan error, 1)
	go func() { serviceDone <- s.Serve(serviceCtx) }()
	defer func() { stopService(); <-serviceDone }()
	socket := filepath.Join(dir, "service/control.sock")
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("service not ready")
		}
		time.Sleep(time.Millisecond)
	}
	target, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(dir, "target.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	t.Setenv("EASYCONNECT_HELPER_TARGET", target.Addr().String())
	exe, _ := os.Executable()
	upstream := Upstream{Address: ready.Address, Username: "test", Password: password, Networks: []netpolicy.Range{{Min: netip.AddrFrom4(base).String(), Max: end.String()}}}
	p, err := launch(ctx, Program{Executable: exe, Args: []string{"-test.run=^TestManagedProgram$"}}, upstream, socket, uint32(os.Getuid()), exe, []string{"-test.run=^TestManagedLaunchBarrier$"})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	target.SetDeadline(time.Now().Add(2 * time.Second))
	conn, err := target.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ce, cd := json.NewEncoder(conn), json.NewDecoder(conn)
	var program probeReply
	if err = cd.Decode(&program); err != nil {
		t.Fatal(err)
	}
	aliases := &aliasRoute{ID: randomID(), UID: os.Getuid(), Prefix: prefix, Groups: []string{program.Group}}
	if err = aliases.install(ctx, systemCommand); err != nil {
		t.Fatal(err)
	}
	defer aliases.remove(ctx, systemCommand)
	journalDir := filepath.Join(dir, "aliases")
	if err := secureDirectory(journalDir, 0700); err != nil {
		t.Fatal(err)
	}
	journal := aliasJournal{Version: 1, ID: aliases.ID, UID: aliases.UID, Prefix: aliases.Prefix, Entries: map[string]aliasRecord{}}
	if err := saveAliasJournal(journalDir, journal); err != nil {
		t.Fatal(err)
	}
	var dnsMu sync.Mutex
	var sequence int
	dnsServer, err := splitdns.Listen(ctx, func(ctx context.Context, packet []byte) ([]byte, error) {
		dnsMu.Lock()
		defer dnsMu.Unlock()
		sequence++
		request := workeripc.Message{Version: workeripc.Version, Session: "alias-fixture", Type: "dns_query", RequestID: strconv.Itoa(sequence), DNS: packet, CaptureDNS: true, CapturePrefix: aliases.Prefix}
		if err := enc.Encode(request); err != nil {
			return nil, err
		}
		var reply workeripc.Message
		if err := dec.Decode(&reply); err != nil {
			return nil, err
		}
		if reply.Error != "" {
			return nil, fmt.Errorf("DNS IPC: %s", reply.Error)
		}
		if err := aliases.publishSaved(ctx, systemCommand, journalDir, &journal, reply.DNSAliases); err != nil {
			return nil, err
		}
		return reply.DNS, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer dnsServer.Close()
	request := func(name string, port int, child bool) probeReply {
		t.Helper()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		if err := ce.Encode(probeRequest{Target: net.JoinHostPort(name, strconv.Itoa(port)), Child: child, DNS: dnsServer.Addr()}); err != nil {
			t.Fatal(err)
		}
		var r probeReply
		if err := cd.Decode(&r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	check := func(r probeReply, want string) {
		t.Helper()
		if r.Error != "" || r.Body != want {
			t.Fatalf("response=%+v want=%q", r, want)
		}
	}
	for _, child := range []bool{false, true} {
		check(request("a.corp.test", portA, child), "vpn:a.corp.test")
		check(request("b.corp.test", portB, child), "vpn:b.corp.test")
		for _, pair := range []struct {
			name string
			port int
		}{{"a.corp.test", portB}, {"b.corp.test", portA}} {
			if r := request(pair.name, pair.port, child); r.Body != "" {
				t.Fatalf("shared-IP authority broadened: %+v", r)
			}
		}
	}
	t.Log("selected program and child retain distinct domain/port authority through actual DNS + TPROXY + private SOCKS")
	for _, name := range []string{"a.corp.test", "b.corp.test"} {
		for _, port := range []int{portA, portB} {
			check(probeWithResolver("tcp4", net.JoinHostPort(name, strconv.Itoa(port)), dnsServer.Addr()), "original")
		}
	}
	t.Log("unselected program restores shared DNS aliases to real IP and keeps its original route")
	q := new(dns.Msg).SetQuestion("a.corp.test.", dns.TypeA)
	m, _, err := (&dns.Client{Net: "tcp", Timeout: time.Second}).Exchange(q, dnsServer.Addr())
	if err != nil || len(m.Answer) != 1 {
		t.Fatal("TCP DNS alias", err)
	}
	fake := m.Answer[0].(*dns.A).A.String()
	if err := aliases.publish(ctx, systemCommand, []workeripc.DNSAlias{{Address: fake, Original: "198.18.0.3", TTL: 60}}); err == nil {
		t.Fatal("alias reassigned to another real address")
	}
	if got := probeNetwork("tcp4", net.JoinHostPort(netip.AddrFrom4(base).Next().String(), strconv.Itoa(portA))); got.Body != "" || got.Error == "" {
		t.Fatal("unissued fake address escaped", got)
	}
	if err := aliases.publish(ctx, systemCommand, []workeripc.DNSAlias{{Address: fake, Original: "198.18.0.2", TTL: 1}}); err != nil {
		t.Fatal(err)
	}
	expiring := end.Prev().String()
	if err := aliases.publish(ctx, systemCommand, []workeripc.DNSAlias{{Address: expiring, Original: "198.18.0.2", TTL: 1}}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	check(probeNetwork("tcp4", net.JoinHostPort(fake, strconv.Itoa(portA))), "original")
	if got := probeNetwork("tcp4", net.JoinHostPort(expiring, strconv.Itoa(portA))); got.Body != "" || got.Error == "" {
		t.Fatal("expired original-path mapping escaped", got)
	}
	t.Log("expired/unissued mappings reject instead of entering the pre-existing broad route")
	m, _, err = (&dns.Client{Net: "tcp", Timeout: time.Second}).Exchange(q, dnsServer.Addr())
	if err != nil || len(m.Answer) != 1 {
		t.Fatal("alias refresh", err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	// Atomically retire selection without deleting the still-cacheable map.
	if err := aliases.setGroups(ctx, systemCommand, nil); err != nil {
		t.Fatal(err)
	}
	check(request(fake, portA, false), "original")
	t.Log("retired scope can use original network after alias restoration; selected permissions are gone")
	// Recover the persisted half of a failed map publication. No DNS answer
	// was returned, but recovery must handle the prepared record as well.
	failedAddress := end.Prev().Prev().String()
	failedRun := func(ctx context.Context, tool, input string, args ...string) ([]byte, error) {
		if tool == "nft" && strings.Contains(input, "add element") {
			return nil, fmt.Errorf("simulated alias publication failure")
		}
		return systemCommand(ctx, tool, input, args...)
	}
	if err := aliases.publishSaved(ctx, failedRun, journalDir, &journal, []workeripc.DNSAlias{{Address: failedAddress, Original: "198.18.0.2", TTL: 30}}); err == nil {
		t.Fatal("publication failure missing")
	}
	persisted, err := readAliasJournal(filepath.Join(journalDir, journal.ID+".json"), os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	now, err := bootNow()
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := restoreAliasJournal(ctx, systemCommand, persisted, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(recovered.Groups) != 0 {
		t.Fatal("recovery restored VPN selection")
	}
	check(probeNetwork("tcp4", net.JoinHostPort(fake, strconv.Itoa(portA))), "original")
	check(probeNetwork("tcp4", net.JoinHostPort(failedAddress, strconv.Itoa(portA))), "original")
	aliases = recovered
	t.Log("crash journal restores original destinations, including prepared publication; no VPN authority restored")
	run("nft", "", "flush", "map", "ip", aliases.table(), "real")
	if err := aliases.publish(ctx, systemCommand, []workeripc.DNSAlias{{Address: fake, Original: "198.18.0.2", TTL: 30}}); err == nil {
		t.Fatal("deleted dynamic map accepted a DNS publication")
	}
	now, err = bootNow()
	if err != nil {
		t.Fatal(err)
	}
	aliases, err = restoreAliasJournal(ctx, systemCommand, persisted, now)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("deleted dynamic destinations prevent DNS publication; recovery restores cached original addresses")
	run("nft", "", "flush", "chain", "ip", aliases.table(), "guard")
	if err := aliases.publish(ctx, systemCommand, []workeripc.DNSAlias{{Address: fake, Original: "198.18.0.2", TTL: 30}}); err == nil {
		t.Fatal("modified alias rules accepted a DNS publication")
	}
	t.Log("missing alias guard prevents further DNS publication; owned cleanup still succeeds")
	if err := aliases.remove(ctx, systemCommand); err != nil {
		t.Fatal(err)
	}
	if got := run("ip", "", "-j", "-4", "route", "show", "table", "all"); got != baselineRoutes {
		t.Fatal("foreign route changed")
	}
	if got := run("ip", "", "-j", "-4", "rule", "show"); got != baselineRules {
		t.Fatal("policy rule leaked")
	}
	if got := run("nft", "", "list", "ruleset"); strings.TrimSpace(got) != "" {
		t.Fatal("capture/alias tables leaked")
	}
}
