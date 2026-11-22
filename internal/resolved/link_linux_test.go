package resolved

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ehzyil/connect-hub/internal/splitdns"
	"github.com/miekg/dns"
)

func TestDomainConfigValidation(t *testing.T) {
	for _, domain := range []string{".", "com", "*.corp.test", "bad corp.test", "127.0.0.1", "corp.test\nDefaultRoute=yes", "a..test", "-bad.test"} {
		if (Config{Address: "127.0.0.1:10053", Domains: []string{domain}}).Validate() == nil {
			t.Fatalf("unsafe domain accepted: %q", domain)
		}
	}
	if err := (Config{Address: "127.0.0.1:10053", Domains: []string{"corp.test", "db.internal"}}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestCheckDomainsDelegateCompatibilityAndErrors(t *testing.T) {
	ctx := context.Background()
	unknownMethod := errors.New("busctl: Call failed: Unknown method ListDelegates or interface org.freedesktop.resolve1.Manager")
	for _, test := range []struct {
		name string
		data string
		err  error
		want bool
	}{
		{name: "systemd before delegate API", err: unknownMethod},
		{name: "new API with no delegates", data: `{"data":[[]]}`},
		{name: "configured delegate", data: `{"data":[[["corp","/org/freedesktop/resolve1/delegate/corp"]]]}`, want: true},
		{name: "permission failure", err: errors.New("access denied"), want: true},
		{name: "malformed response", data: `not json`, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := checkDomains(ctx, func(_ context.Context, tool, _ string, args ...string) ([]byte, error) {
				if tool != "busctl" || len(args) == 0 {
					t.Fatalf("unexpected command: %s %v", tool, args)
				}
				if args[len(args)-1] == "Domains" {
					return []byte(`{"data":[]}`), nil
				}
				if args[len(args)-1] != "ListDelegates" {
					t.Fatalf("unexpected busctl arguments: %v", args)
				}
				if test.err != nil {
					return nil, test.err
				}
				return []byte(test.data), nil
			}, []string{"corp.test"}, 0)
			if (err != nil) != test.want {
				t.Fatalf("checkDomains() error=%v, want error=%t", err, test.want)
			}
		})
	}
}

func namespaceCommand(ctx context.Context, tool, input string, args ...string) ([]byte, error) {
	if tool != "ip" && tool != "busctl" {
		return nil, errors.New("unsupported test command")
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/"+tool, args...)
	cmd.Env = []string{"PATH=/usr/bin:/usr/sbin", "LC_ALL=C"}
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %s", tool, err, out)
	}
	return out, nil
}

// Runs inside the private resolved instance started by the Python harness.
func TestResolvedNamespaceLifecycle(t *testing.T) {
	if os.Getenv("ECH_RESOLVED_NAMESPACE") != "1" {
		t.Skip("run scripts/test-resolved-linux.sh")
	}
	host := os.Getenv("ECH_PROBE_HOST_NETNS")
	self, err := os.Readlink("/proc/self/ns/net")
	if err != nil || host == "" || self == host {
		t.Fatal("refusing host DNS mutation")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	answer := func(_ context.Context, packet []byte) ([]byte, error) {
		q := new(dns.Msg)
		if err := q.Unpack(packet); err != nil {
			return nil, err
		}
		m := new(dns.Msg).SetReply(q)
		if q.Question[0].Qtype == dns.TypeA {
			m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 23}, A: net.ParseIP("10.42.0.8")}}
		}
		return m.Pack()
	}
	server, err := splitdns.Listen(ctx, answer)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	run := Command(namespaceCommand)
	// Reproduce the broad transport route observed on the host without
	// changing its real TUN. Only a concrete link-local allocation conflicts.
	for _, args := range [][]string{
		{"link", "add", "dnstransport", "type", "dummy"},
		{"link", "set", "dnstransport", "up"},
		{"route", "add", "168.0.0.0/6", "dev", "dnstransport"},
		{"route", "add", "169.254.0.0/16", "dev", "dnstransport"},
	} {
		if _, err := run(ctx, "ip", "", args...); err != nil {
			t.Fatal(err)
		}
	}
	config := Config{Address: server.Addr(), Domains: []string{"corp.test"}}
	if _, err := Prepare(ctx, run, config); err == nil {
		t.Fatal("existing link-local subnet was reused")
	}
	if _, err := run(ctx, "ip", "", "route", "del", "169.254.0.0/16", "dev", "dnstransport"); err != nil {
		t.Fatal(err)
	}
	beforeRoutes, err := run(ctx, "ip", "", "-j", "-4", "route", "show", "table", "all")
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := Prepare(ctx, run, Config{Address: server.Addr(), Domains: []string{"other.test"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := Install(ctx, run, *foreign); err != nil {
		t.Fatal(err)
	}
	defer Remove(context.Background(), run, *foreign)
	lease, err := Prepare(ctx, run, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := Install(ctx, run, *lease); err != nil {
		t.Fatal(err)
	}
	defer Remove(context.Background(), run, *lease)
	if err := Verify(ctx, run, *lease); err != nil {
		t.Fatal(err)
	}
	q := new(dns.Msg).SetQuestion("app.corp.test.", dns.TypeA)
	for _, network := range []string{"udp", "tcp"} {
		m, _, err := (&dns.Client{Net: network, Timeout: time.Second}).Exchange(q, "127.0.0.53:53")
		if err != nil || m.Rcode != dns.RcodeSuccess || len(m.Answer) != 1 || m.Answer[0].(*dns.A).A.String() != "10.42.0.8" {
			t.Fatalf("system stub %s: %v %v", network, m, err)
		}
	}
	t.Log("owned link: system stub UDP/TCP reaches session DNS")
	for _, domains := range [][]string{{"corp.test"}, {"child.corp.test"}, {"test.corp.test", "corp.test"}} {
		sort.Strings(domains)
		if _, err := Prepare(ctx, run, Config{Address: server.Addr(), Domains: domains}); err == nil {
			t.Fatal("DNS domain conflict was accepted")
		}
	}
	if err := Remove(ctx, run, *lease); err != nil {
		t.Fatal(err)
	}
	if err := Verify(ctx, run, *foreign); err != nil {
		t.Fatalf("foreign DNS changed: %v", err)
	}
	if err := Remove(ctx, run, *lease); err != nil {
		t.Fatal("cleanup is not idempotent")
	}
	if err := Verify(ctx, run, *lease); err == nil {
		t.Fatal("deleted link still verifies")
	}
	t.Log("cleanup removes only owned link and retains foreign policy")
	// Interrupted installations can be recovered before every DNS property exists.
	lease, err = Prepare(ctx, run, config)
	if err != nil {
		t.Fatal(err)
	}
	failed := Command(func(ctx context.Context, tool, input string, args ...string) ([]byte, error) {
		if tool == "busctl" && strings.Contains(strings.Join(args, " "), "SetLinkDomains") {
			return nil, errors.New("injected domain installation failure")
		}
		return run(ctx, tool, input, args...)
	})
	if err := Install(ctx, failed, *lease); err == nil {
		t.Fatal("expected installation failure")
	}
	if err := Remove(ctx, run, *lease); err != nil {
		t.Fatal(err)
	}
	t.Log("partial DNS installation can be rolled back without reverting other links")
	// A reused interface name with a different owner must never be deleted.
	if _, err := run(ctx, "ip", "", "link", "add", "name", lease.Name(), "alias", "foreign-owner", "type", "dummy"); err != nil {
		t.Fatal(err)
	}
	if err := Remove(ctx, run, *lease); err == nil {
		t.Fatal("foreign interface deleted")
	}
	b, err := run(ctx, "ip", "", "-j", "link", "show", "dev", lease.Name())
	if err != nil {
		t.Fatal(err)
	}
	var got []map[string]any
	if json.Unmarshal(b, &got) != nil || len(got) != 1 {
		t.Fatal("foreign interface missing")
	}
	_, _ = run(ctx, "ip", "", "link", "delete", "dev", lease.Name())
	if err := Remove(ctx, run, *foreign); err != nil {
		t.Fatal(err)
	}
	afterRoutes, err := run(ctx, "ip", "", "-j", "-4", "route", "show", "table", "all")
	if err != nil || string(beforeRoutes) != string(afterRoutes) {
		t.Fatal("DNS lifecycle changed the pre-existing transport route", err)
	}
	t.Log("broad TUN transport route coexists with DNS link; concrete link-local subnet remains protected")
}
