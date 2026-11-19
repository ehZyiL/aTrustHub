package capture

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qy/easyconnect/internal/proxy"
)

type probeRequest struct {
	Target  string
	Child   bool
	Network string
	DNS     string
}
type probeReply struct{ Group, Body, Error string }

func probeGet(target string) probeReply {
	return probeNetwork("tcp4", target)
}

func probeNetwork(network, target string) probeReply {
	return probeWithResolver(network, target, "")
}
func probeWithResolver(network, target, dnsAddress string) probeReply {
	if network == "" {
		network = "tcp4"
	}
	dialer := net.Dialer{Timeout: 700 * time.Millisecond}
	if dnsAddress != "" {
		dialer.Resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, dnsAddress)
		}}
	}
	c, err := dialer.Dial(network, target)
	if err != nil {
		return probeReply{Error: err.Error()}
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	_, _ = io.WriteString(c, "hello\n")
	if strings.HasPrefix(network, "udp") {
		b := make([]byte, 1024)
		n, err := c.Read(b)
		if err != nil {
			return probeReply{Error: err.Error()}
		}
		return probeReply{Body: string(b[:n])}
	}
	b, err := io.ReadAll(c)
	if err != nil {
		return probeReply{Error: err.Error()}
	}
	return probeReply{Body: string(b)}
}

func TestCaptureProbeChild(t *testing.T) {
	if os.Getenv("EASYCONNECT_CAPTURE_CHILD") != "1" {
		t.Skip("subprocess only")
	}
	var req probeRequest
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		t.Fatal(err)
	}
	_ = json.NewEncoder(os.Stdout).Encode(probeWithResolver(req.Network, req.Target, req.DNS))
}

func TestCaptureProbeProcess(t *testing.T) {
	if os.Getenv("EASYCONNECT_CAPTURE_PROCESS") != "1" {
		t.Skip("subprocess only")
	}
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	group := strings.TrimPrefix(strings.TrimSpace(string(b)), "0::/")
	enc, dec := json.NewEncoder(os.Stdout), json.NewDecoder(os.Stdin)
	_ = enc.Encode(probeReply{Group: group})
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
			cmd.Stdin = bytes.NewReader(b)
			out, err := cmd.Output()
			if err != nil {
				reply.Error = err.Error()
			} else if err := json.NewDecoder(bytes.NewReader(out)).Decode(&reply); err != nil {
				reply.Error = err.Error()
			}
		} else {
			reply = probeGet(req.Target)
		}
		_ = enc.Encode(reply)
	}
}

// This test intentionally needs an empty private network namespace. Regular
// unit tests skip it; scripts/test-capture-linux.sh supplies one without sudo.
func TestCaptureNamespace(t *testing.T) {
	if os.Getenv("EASYCONNECT_CAPTURE_NETNS") != "1" {
		t.Skip("run scripts/test-capture-linux.sh")
	}
	self, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	host := os.Getenv("EASYCONNECT_CAPTURE_HOST_NETNS")
	if host == "" || host == self {
		t.Fatal("refusing to change host network namespace")
	}
	ifaces, err := net.Interfaces()
	if err != nil || len(ifaces) != 1 || ifaces[0].Name != "lo" {
		t.Fatal("test requires a new network namespace containing only lo")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	run := func(input string, args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(ctx, args[0], args[1:]...)
		cmd.Stdin = strings.NewReader(input)
		b, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v: %s", args[0], err, b)
		}
		return string(b)
	}
	if strings.TrimSpace(run("", "nft", "list", "ruleset")) != "" {
		t.Fatal("test namespace rules are not empty")
	}
	run("", "ip", "link", "set", "lo", "up")
	run("", "ip", "link", "add", "ecprobe", "type", "dummy")
	run("", "ip", "addr", "add", "198.18.0.1/24", "dev", "ecprobe")
	run("", "ip", "addr", "add", "198.18.0.2/32", "dev", "ecprobe")
	run("", "ip", "link", "set", "ecprobe", "up")
	defer func() { _ = exec.Command("ip", "link", "del", "ecprobe").Run() }()
	// A local endpoint distinguishes unselected direct requests from requests
	// captured and relayed by the mock SOCKS server.
	direct, err := net.Listen("tcp4", "198.18.0.2:0")
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Close()
	loop, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer loop.Close()
	respond := func(ln net.Listener, body string) {
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer c.Close()
					_ = c.SetDeadline(time.Now().Add(time.Second))
					_, _ = c.Read(make([]byte, 32))
					_, _ = io.WriteString(c, body)
				}()
			}
		}()
	}
	respond(direct, "direct")
	respond(loop, "loopback")
	var failed atomic.Bool
	targets := make(chan string, 16)
	socks := proxy.New(proxy.Options{Addr: "127.0.0.1:0", Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		targets <- address
		if failed.Load() {
			return nil, errors.New("simulated tunnel failure")
		}
		a, b := net.Pipe()
		go func() {
			defer b.Close()
			_ = b.SetDeadline(time.Now().Add(time.Second))
			_, _ = b.Read(make([]byte, 32))
			_, _ = io.WriteString(b, "captured")
		}()
		return a, nil
	}})
	if err := socks.Start(); err != nil {
		t.Fatal(err)
	}
	defer socks.Close()
	d, _ := proxy.NewSOCKSDialer(socks.Addr().String(), nil)
	ingress, err := ListenTCP(ctx, "127.0.0.1:0", d.DialContext)
	if err != nil {
		t.Fatal(err)
	}
	defer ingress.Close()
	exe, _ := os.Executable()
	unit := fmt.Sprintf("easyconnect-capture-probe-%d", os.Getpid())
	cmd := exec.CommandContext(ctx, "systemd-run", "--user", "--scope", "--quiet", "--collect", "--expand-environment=no", "--unit="+unit, exe, "-test.run=^TestCaptureProbeProcess$")
	cmd.Env = append(os.Environ(), "EASYCONNECT_CAPTURE_PROCESS=1")
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = input.Close()
		if err := cmd.Wait(); err != nil {
			t.Errorf("probe process: %v: %s", err, stderr.String())
		}
	}()
	dec, enc := json.NewDecoder(output), json.NewEncoder(input)
	var ready probeReply
	if err := dec.Decode(&ready); err != nil {
		t.Fatalf("probe ready: %v", err)
	}
	if !strings.HasSuffix(ready.Group, "/"+unit+".scope") {
		t.Fatalf("unexpected scope %q", ready.Group)
	}
	level := len(strings.Split(ready.Group, "/"))
	_, port, _ := net.SplitHostPort(ingress.Addr().String())
	rules := fmt.Sprintf(`table ip easyconnect_probe {
 chain out {
  type route hook output priority mangle; policy accept;
  ip daddr 127.0.0.0/8 return
  ip protocol tcp socket cgroupv2 level %d "%s" meta mark set 0x40000000
 }
 chain pre {
  type filter hook prerouting priority mangle; policy accept;
  meta mark 0x40000000 ip protocol tcp tproxy to 127.0.0.1:%s accept
 }
}`, level, ready.Group, port)
	run("", "ip", "rule", "add", "pref", "100", "fwmark", "0x40000000/0x40000000", "lookup", "11452")
	run("", "ip", "route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", "11452")
	defer func() {
		_ = exec.Command("ip", "rule", "del", "pref", "100").Run()
		_ = exec.Command("ip", "route", "flush", "table", "11452").Run()
	}()
	run(rules, "nft", "-f", "-")
	defer func() { _ = exec.Command("nft", "delete", "table", "ip", "easyconnect_probe").Run() }()
	request := func(target string, child bool) probeReply {
		t.Helper()
		if err := enc.Encode(probeRequest{Target: target, Child: child}); err != nil {
			t.Fatal(err)
		}
		var result probeReply
		if err := dec.Decode(&result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	check := func(reply probeReply, want string) {
		t.Helper()
		if reply.Error != "" || reply.Body != want {
			t.Fatalf("response=%+v want=%s", reply, want)
		}
	}
	check(request(direct.Addr().String(), false), "captured")
	if got := <-targets; got != direct.Addr().String() {
		t.Fatalf("original target=%s", got)
	}
	t.Log("selected process: transparent TCP -> existing SOCKS, original target preserved")
	check(request(direct.Addr().String(), true), "captured")
	<-targets
	t.Log("new child process: inherits cgroup capture without proxy settings")
	check(probeGet(direct.Addr().String()), "direct")
	check(request(loop.Addr().String(), false), "loopback")
	t.Log("unselected process and selected loopback request: original paths preserved")
	// This target has no local address/listener: capture requires the marked
	// policy route rather than merely intercepting local loopback delivery.
	_, targetPort, _ := net.SplitHostPort(direct.Addr().String())
	remote := net.JoinHostPort("198.18.0.3", targetPort)
	check(request(remote, false), "captured")
	if got := <-targets; got != remote {
		t.Fatalf("policy-routed target=%s", got)
	}
	t.Log("nonlocal destination: mark + policy route + TPROXY verified")
	failed.Store(true)
	if reply := request(direct.Addr().String(), false); reply.Body != "" {
		t.Fatalf("upstream failure fell back: %+v", reply)
	}
	<-targets
	check(probeGet(direct.Addr().String()), "direct")
	t.Log("upstream failure: no direct fallback; unselected traffic still works")
	run("", "nft", "delete", "table", "ip", "easyconnect_probe")
	run("", "ip", "rule", "del", "pref", "100")
	run("", "ip", "route", "flush", "table", "11452")
	check(request(direct.Addr().String(), false), "direct")
	if strings.TrimSpace(run("", "nft", "list", "ruleset")) != "" {
		t.Fatal("nft rules leaked")
	}
	if strings.Contains(run("", "ip", "rule", "show"), "11452") {
		t.Fatal("policy rule leaked")
	}
	t.Log("owned rules removed: same selected process uses original path again")
}
