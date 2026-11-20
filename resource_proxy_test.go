package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCaptureProxySwitchRestoresOnlyItsUnchangedWrite(t *testing.T) {
	before := captureProxySnapshot{Enabled: 1, Server: "socks=127.0.0.1:1080", Fingerprint: "settings-1"}
	for _, external := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "proxy.json")
		current := before
		writes := 0
		ops := captureProxyOps{read: func() (captureProxySnapshot, error) { return current, nil }, setEnabled: func(v uint64) error { writes++; current.Enabled = v; return nil }}
		restore, err := suspendOwnedProxy(path, "127.0.0.1:1080", ops)
		if err != nil {
			t.Fatal(err)
		}
		if current.Enabled != 0 || writes != 1 {
			t.Fatal("proxy not suspended")
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatal("recovery not durable", err)
		}
		if external {
			current.Server = "other-proxy:1080"
			current.Fingerprint = "settings-2"
		}
		err = restore()
		if external {
			if err == nil || writes != 1 || current.Server != "other-proxy:1080" {
				t.Fatal("overwrote external proxy")
			}
			current = before
			current.Enabled = 0
			if err := restore(); err != nil {
				t.Fatal("cleanup cannot retry", err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
		if current != before || writes != 2 {
			t.Fatal("previous proxy not restored")
		}
		if err := restore(); err != nil || writes != 2 {
			t.Fatal("restore not idempotent")
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("recovery journal left behind")
		}
	}
}

func TestCaptureProxyRetainsFailedRestore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy.json")
	current := captureProxySnapshot{Enabled: 1, Server: "socks=127.0.0.1:1080", Fingerprint: "x"}
	writes := 0
	fail := false
	ops := captureProxyOps{read: func() (captureProxySnapshot, error) { return current, nil }, setEnabled: func(v uint64) error {
		if fail {
			return errors.New("registry locked")
		}
		writes++
		current.Enabled = v
		return nil
	}}
	restore, err := suspendOwnedProxy(path, "127.0.0.1:1080", ops)
	if err != nil {
		t.Fatal(err)
	}
	fail = true
	if err := restore(); err == nil {
		t.Fatal("failed restore hidden")
	}
	if _, err := suspendOwnedProxy(path, "127.0.0.1:1080", ops); err == nil {
		t.Fatal("unresolved journal overwritten")
	}
	fail = false
	if err := restore(); err != nil {
		t.Fatal(err)
	}
}

func TestCaptureProxyCoexistsWithExternalProxyWithoutChangingIt(t *testing.T) {
	for _, automatic := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "proxy.json")
		current := captureProxySnapshot{Enabled: 1, Server: "127.0.0.1:10808", Fingerprint: "v2rayN", Automatic: automatic}
		writes := 0
		ops := captureProxyOps{read: func() (captureProxySnapshot, error) { return current, nil }, setEnabled: func(uint64) error { writes++; return nil }}
		restore, err := suspendOwnedProxy(path, "127.0.0.1:1080", ops)
		if err != nil || restore == nil {
			t.Fatalf("external proxy unnecessarily blocked resource capture: %v", err)
		}
		current.Server = "127.0.0.1:10809" // External owner changes its settings during capture.
		if err := restore(); err != nil || writes != 0 || current.Server != "127.0.0.1:10809" {
			t.Fatal("capture stop touched external proxy", err)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("created a recovery journal for settings we do not own")
		}
	}
}
