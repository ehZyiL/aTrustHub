package capture

import (
	"context"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

func TestSystemDeviceOwnsOnlyItsInterfaceInNamespace(t *testing.T) {
	if os.Getenv("EASYCONNECT_SYSTEM_TUN_NAMESPACE") != "1" || os.Geteuid() != 0 {
		t.Skip("requires root in a disposable network namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
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
	if err := device.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := net.InterfaceByName(device.name); err == nil {
		t.Fatal("interface survived closure")
	}
}
