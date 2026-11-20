package capture

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qy/easyconnect/internal/proxy"
	"github.com/qy/easyconnect/internal/resolved"
	"github.com/qy/easyconnect/internal/workeripc"
)

// Run with the private resolved/network/mount namespace probe. No host
// network configuration or real VPN session is used by this regression.
func TestSystemSharedAliasPoolTransferInResolvedNamespace(t *testing.T) {
	if os.Getenv("ECH_RESOLVED_NAMESPACE") != "1" {
		t.Skip("requires scripts/probe-resolved-namespace.py")
	}
	host := os.Getenv("ECH_PROBE_HOST_NETNS")
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil || host == "" || current == host {
		t.Fatal("refusing to change host network")
	}
	testSystemSharedAliasPoolTransfer(t, true)
}

func TestSystemSharedAliasPoolTransferInNamespace(t *testing.T) {
	requireSystemNamespace(t)
	testSystemSharedAliasPoolTransfer(t, false)
}

func testSystemSharedAliasPoolTransfer(t *testing.T, realDNS bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if _, err := systemCommand(ctx, "ip", "", "link", "set", "lo", "up"); err != nil {
		t.Fatal(err)
	}
	// Cached synthetic destinations need an initial original-egress route
	// before the OUTPUT DNAT hook runs, just as on a connected desktop.
	for _, args := range [][]string{
		{"link", "add", "echaliasold", "type", "dummy"},
		{"addr", "add", "192.0.2.2/24", "dev", "echaliasold"},
		{"link", "set", "echaliasold", "up"},
		{"route", "add", "default", "dev", "echaliasold"},
		{"addr", "add", "203.0.113.40/32", "dev", "lo"},
	} {
		if _, err := systemCommand(ctx, "ip", "", args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = systemCommand(context.Background(), "ip", "", "link", "del", "echaliasold")
		_, _ = systemCommand(context.Background(), "ip", "", "addr", "del", "203.0.113.40/32", "dev", "lo")
	})
	s, err := newService(1000, filepath.Join(t.TempDir(), "capture"), systemCommand)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	owner := strings.Repeat("b", 64)
	a, err := s.prepareAliases(ctx, owner, aliasRequest{DNS: resolved.Config{Address: "127.0.0.1:12345", Domains: []string{"corp.test"}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, alias := range s.aliases {
			_ = alias.route.remove(context.Background(), s.run)
		}
	})
	seedAddr := netip.MustParsePrefix(a.route.Prefix).Addr().Next().String()
	seed := []workeripc.DNSAlias{{Address: seedAddr, Original: "203.0.113.40", TTL: 30}}
	if err := a.route.publishSaved(ctx, s.run, s.aliasDir(), &a.journal, seed); err != nil {
		t.Fatal(err)
	}
	direct, err := net.Listen("tcp4", "203.0.113.40:0")
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Close()
	go func() {
		conn, err := direct.Accept()
		if err == nil {
			defer conn.Close()
			_, _ = io.WriteString(conn, "original")
		}
	}()
	password := strings.Repeat("a", 64)
	socks := proxy.New(proxy.Options{Addr: "127.0.0.1:0", Context: ctx, SOCKSOnly: true,
		Auth: &proxy.Auth{Username: "system", Credential: password},
		Dial: func(_ context.Context, _, address string) (net.Conn, error) {
			left, right := net.Pipe()
			go func() { defer right.Close(); _, _ = io.WriteString(right, address) }()
			return left, nil
		}})
	if err := socks.Start(); err != nil {
		t.Fatal(err)
	}
	defer socks.Close()
	// Decode the wire format so this regression reaches the old production
	// path as well: old helpers ignored the reference and rejected the pool.
	wire, _ := json.Marshal(map[string]any{"upstream": Upstream{Address: socks.Addr().String(), Username: "system", Password: password},
		"dnsAddress": "127.0.0.1:12346", "resources": []any{map[string]any{
			"id": strings.Repeat("c", 32), "gateway": "203.0.113.1", "domains": []string{"corp.test"},
			"requiredPrefix": a.route.Prefix, "alias": AliasRef{ID: a.route.ID, Token: owner}}}})
	var config SystemConfig
	if err := json.Unmarshal(wire, &config); err != nil {
		t.Fatal(err)
	}
	if !realDNS {
		// Exercise actual nft/TUN/policy routing and the service transfer path,
		// while replacing only the pre-existing resolved link. DNS policy
		// installation itself is covered by the separate resolved probe.
		kernel, err := snapshot(ctx, s.run)
		if err != nil {
			t.Fatal(err)
		}
		kernel.routes = append(kernel.routes, map[string]any{"dst": a.route.Prefix})
		runtime, err := newSystemRuntime(ctx, s.run, s.systemJournalPath(), strings.Repeat("d", 64), config, kernel, nil)
		if err != nil {
			t.Fatal(err)
		}
		runtime.unlock, err = s.lockCaptureMode(true)
		if err != nil {
			t.Fatal(err)
		}
		s.system = runtime
		if err := runtime.installRule(ctx); err != nil {
			t.Fatal(err)
		}
		runtime.journal.DNS = &resolved.Lease{ID: strings.Repeat("e", 32), Address: "169.254.42.1", Config: resolved.Config{Address: config.DNSAddress, Domains: []string{"corp.test"}}}
	}
	start := frame{Type: "system_start", System: &config}
	if !realDNS {
		start.Type = "system_sync"
		// Fail after suspension, at the first route installation, and require
		// the original recovery table to be restored by transaction rollback.
		run := s.system.run
		s.system.run = func(ctx context.Context, tool, input string, args ...string) ([]byte, error) {
			if tool == "ip" && len(args) > 2 && args[1] == "route" && args[2] == "add" {
				return nil, errors.New("injected pool route failure")
			}
			return run(ctx, tool, input, args...)
		}
		if _, err := s.systemControl(ctx, strings.Repeat("d", 64), start); err == nil || a.dormant {
			t.Fatal("failed transfer did not restore software recovery", err)
		}
		s.system.run = run
		// If rollback itself fails, the suspended lease never reaches pools.
		// The same recovery used by stop must still find it via the service.
		s.system.run = func(ctx context.Context, tool, input string, args ...string) ([]byte, error) {
			if tool == "ip" && len(args) > 2 && args[1] == "route" && args[2] == "add" ||
				tool == "nft" && strings.Contains(input, "create table ip "+a.route.table()) {
				return nil, errors.New("injected transfer and rollback failure")
			}
			return run(ctx, tool, input, args...)
		}
		if _, err := s.systemControl(ctx, strings.Repeat("d", 64), start); err == nil || !a.dormant || len(s.system.pools) != 0 {
			t.Fatal("fixture did not retain an uncommitted suspended lease", err)
		}
		s.system.run = run
		if err := s.system.restoreSharedAliases(ctx, s.aliases); err != nil || a.dormant {
			t.Fatal("cleanup lost an uncommitted recovery table", err)
		}
	}
	state, err := s.systemControl(ctx, strings.Repeat("d", 64), start)
	if err != nil {
		t.Fatalf("same live software pool must transfer without relogin: %v", err)
	}
	if !a.dormant || state.State.Prefixes[strings.Repeat("c", 32)] != a.route.Prefix {
		t.Fatal("system capture did not retain the shared pool")
	}
	if s.system.pools[strings.Repeat("c", 32)].Entries[netip.MustParseAddr(seedAddr)] != a.journal.Entries[seedAddr] {
		t.Fatal("a still-cacheable software mapping was lost during transfer")
	}
	addr := netip.MustParsePrefix(a.route.Prefix).Addr().Next().String()
	aliases := []workeripc.DNSAlias{{Address: addr, Original: "203.0.113.40", TTL: 30}}
	if _, err := s.systemControl(ctx, strings.Repeat("d", 64), frame{Type: "system_publish", ID: strings.Repeat("c", 32), Mappings: aliases}); err != nil {
		t.Fatal(err)
	}
	conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp4", net.JoinHostPort(addr, "443"))
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	body, err := io.ReadAll(conn)
	conn.Close()
	if err != nil || string(body) != net.JoinHostPort(addr, "443") {
		t.Fatal("shared pool traffic missed system TUN", string(body), err)
	}
	journal, err := readAliasJournal(filepath.Join(s.aliasDir(), a.route.ID+".json"), s.uid)
	if err != nil || journal.Entries[addr].Original != aliases[0].Original {
		t.Fatal("system publication was not saved for returning to software mode", err)
	}
	runtime := s.system
	run := runtime.run
	restored := false
	runtime.run = func(ctx context.Context, tool, input string, args ...string) ([]byte, error) {
		if tool == "nft" && strings.Contains(input, "create table ip "+a.route.table()) {
			if runtime.ctx.Err() == nil {
				t.Error("return-path restoration began before forwarding was cancelled")
			}
			restored = true
		}
		if tool == "ip" && len(args) > 2 && args[1] == "rule" && args[2] == "del" && !restored {
			t.Error("routing guard was removed before original-destination restoration")
		}
		return run(ctx, tool, input, args...)
	}
	if _, err := s.systemControl(ctx, strings.Repeat("d", 64), frame{Type: "system_stop"}); err != nil {
		t.Fatal(err)
	}
	if !restored {
		t.Fatal("stop skipped shared recovery table restoration")
	}
	if a.dormant || len(a.route.Groups) != 0 {
		t.Fatal("stop did not restore original-path recovery without software selection")
	}
	a.route.mu.Lock()
	err = a.route.verifyLocked(ctx, s.run)
	a.route.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	cached, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp4", net.JoinHostPort(addr, strings.Split(direct.Addr().String(), ":")[1]))
	if err != nil {
		t.Fatal("cached address did not return to its original egress", err)
	}
	_ = cached.SetReadDeadline(time.Now().Add(time.Second))
	data, err := io.ReadAll(cached)
	cached.Close()
	if err != nil || string(data) != "original" {
		t.Fatal("cached address reached the wrong return path", string(data), err)
	}
	// Re-enter using the same capability while its system journal still has
	// an unexpired reservation. Cached identity and expiry must not change.
	expiry := a.journal.Entries[addr].Expires
	if !realDNS {
		kernel, err := snapshot(ctx, s.run)
		if err != nil {
			t.Fatal(err)
		}
		kernel.routes = append(kernel.routes, map[string]any{"dst": a.route.Prefix})
		runtime, err := newSystemRuntime(ctx, s.run, s.systemJournalPath(), strings.Repeat("d", 64), config, kernel, map[string]int64{a.route.Prefix: journal.retirement()})
		if err != nil {
			t.Fatal(err)
		}
		runtime.unlock, err = s.lockCaptureMode(true)
		if err != nil {
			t.Fatal(err)
		}
		s.system = runtime
		if err := runtime.installRule(ctx); err != nil {
			t.Fatal(err)
		}
		runtime.journal.DNS = &resolved.Lease{ID: strings.Repeat("e", 32), Address: "169.254.42.1", Config: resolved.Config{Address: config.DNSAddress, Domains: []string{"corp.test"}}}
	}
	if _, err := s.systemControl(ctx, strings.Repeat("d", 64), start); err != nil {
		t.Fatal("same live capability could not reuse its retirement reservation", err)
	}
	pool := s.system.pools[strings.Repeat("c", 32)]
	if pool.Entries[netip.MustParseAddr(addr)].Expires != expiry {
		t.Fatal("mode transfer changed the published lifetime")
	}
}
