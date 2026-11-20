package capture

import (
	"context"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSystemDeviceOwnsOnlyItsInterfaceInNamespace(t *testing.T) {
	requireSystemNamespace(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	testSystemDevice(t, ctx)
}

func requireSystemNamespace(t *testing.T) {
	t.Helper()
	if os.Getenv("EASYCONNECT_SYSTEM_TUN_NAMESPACE") != "1" || os.Geteuid() != 0 {
		t.Skip("requires root in a disposable network namespace")
	}
	host := os.Getenv("EASYCONNECT_SYSTEM_TUN_HOST_NETNS")
	self, err := os.Readlink("/proc/self/ns/net")
	if err != nil || host == "" || host == self {
		t.Fatalf("refusing to change host network: %v", err)
	}
}

func testSystemDevice(t *testing.T, ctx context.Context) {
	id := strings.Repeat("a", 32)
	source := netip.MustParseAddr("198.18.42.1")
	rules := func() string {
		out, err := systemCommand(ctx, "ip", "", "-j", "rule", "show")
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	}
	before := rules()
	state, err := snapshot(ctx, systemCommand)
	if err != nil {
		t.Fatal(err)
	}
	allocation, err := allocateRouting(state)
	if err != nil {
		t.Fatal(err)
	}
	owned := systemRoutes{routingAllocation: allocation, ID: id, Source: source}
	device, err := openSystemDevice(ctx, systemCommand, id, source)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = device.Close() })
	iface, err := net.InterfaceByName(device.name)
	if err != nil || iface.Flags&net.FlagUp == 0 {
		t.Fatal("system TUN did not come up", err)
	}
	if duplicate, err := openSystemDevice(ctx, systemCommand, id, source); err == nil {
		_ = duplicate.Close()
		t.Fatal("existing interface adopted")
	}
	if rules() != before {
		t.Fatal("device added external policy rules")
	}
	prefix := netip.MustParsePrefix("192.0.2.40/32")
	if err := owned.changeRoute(ctx, systemCommand, "add", prefix); err != nil {
		t.Fatal(err)
	}
	if err := owned.addRule(ctx, systemCommand); err != nil {
		t.Fatal(err)
	}
	state, err = snapshot(ctx, systemCommand)
	if err != nil {
		t.Fatal(err)
	}
	if err := owned.verify(state, map[netip.Prefix]bool{prefix: true}); err != nil {
		t.Fatal(err)
	}
	out, err := systemCommand(ctx, "ip", "", "-4", "route", "get", prefix.Addr().String())
	if err != nil || !strings.Contains(string(out), device.name) {
		t.Fatal("system policy did not select TUN", string(out), err)
	}
	if out, err := systemCommand(ctx, "ip", "", "-4", "route", "get", prefix.Addr().String(), "mark", strconv.FormatUint(uint64(owned.Mark), 10)); err == nil {
		t.Fatal("original egress still used system routes", string(out))
	}
	if err := owned.removeRule(ctx, systemCommand); err != nil || rules() != before {
		t.Fatal("system routing rule remained after cleanup", err)
	}
	if err := device.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := net.InterfaceByName(device.name); err == nil {
		t.Fatal("interface survived closure")
	}
}
