package wincapture

import (
	"errors"
	"net"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestHelperCleanupRequiresExitAdapterRemovalAndDNSRecovery(t *testing.T) {
	id := strings.Repeat("a", 32)
	for _, test := range []struct {
		name        string
		active      bool
		interfaces  []net.Interface
		journal     bool
		failedProbe string
		wantError   string
	}{
		{name: "complete", interfaces: []net.Interface{{Name: "singbox_tun"}, {Name: "ECH-other-runtime"}}},
		{name: "helper_alive", active: true, wantError: "仍在运行"},
		{name: "adapter_remains", interfaces: []net.Interface{{Name: "ECH-" + id[:12]}}, wantError: "网卡尚未移除"},
		{name: "DNS_pending", journal: true, wantError: "DNS 恢复尚未完成"},
		{name: "process_check_error", failedProbe: "process", wantError: "确认网络助手退出"},
		{name: "adapter_check_error", failedProbe: "interfaces", wantError: "确认接管网卡已移除"},
		{name: "journal_check_error", failedProbe: "journal", wantError: "确认 DNS 恢复完成"},
	} {
		t.Run(test.name, func(t *testing.T) {
			failure := func(name string) error {
				if test.failedProbe == name {
					return errors.New("access denied")
				}
				return nil
			}
			err := confirmHelperCleanup(id, helperCleanupProbe{
				active:     func() (bool, error) { return test.active, failure("process") },
				interfaces: func() ([]net.Interface, error) { return test.interfaces, failure("interfaces") },
				journal:    func() (bool, error) { return test.journal, failure("journal") },
			})
			if test.wantError == "" && err != nil || test.wantError != "" && (err == nil || !strings.Contains(err.Error(), test.wantError)) {
				t.Fatalf("cleanup error = %v, want %q", err, test.wantError)
			}
		})
	}
	if err := confirmHelperCleanup("invalid", helperCleanupProbe{}); err == nil {
		t.Fatal("invalid recovery identity accepted")
	}
}

func TestHelperCleanupProcessIdentityDoesNotMistakeLiveOrReusedPID(t *testing.T) {
	identity, err := processIdentity(windows.CurrentProcess(), uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	if active, err := helperIdentityActive(identity); err != nil || !active {
		t.Fatal("live helper identity treated as exited", active, err)
	}
	identity.Created--
	if active, err := helperIdentityActive(identity); err != nil || active {
		t.Fatal("reused PID treated as the old helper", active, err)
	}
	if _, err := helperIdentityActive(Identity{}); err == nil {
		t.Fatal("missing process identity accepted")
	}
}
