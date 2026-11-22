package model

import "testing"

func TestIsLoopbackHost(t *testing.T) {
	for _, tc := range []struct {
		host string
		want bool
	}{
		{"127.0.0.1", true}, {"::1", true}, {"[::1]", true},
		{"localhost", true}, {"LOCALHOST", true}, {"127.1.2.3", true},
		{"0.0.0.0", false}, {"::", false}, {"192.168.1.10", false},
		{"", false}, {"example.com", false},
	} {
		if got := IsLoopbackHost(tc.host); got != tc.want {
			t.Errorf("IsLoopbackHost(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

func TestSettingsRequirePasswordOffLoopback(t *testing.T) {
	lan := DefaultSettings()
	lan.ListenHost = "0.0.0.0"
	if err := lan.Validate(); err == nil {
		t.Fatal("LAN listener without a password was accepted")
	}
	lan.ProxyPassword = "short"
	if err := lan.Validate(); err == nil {
		t.Fatal("a 5-character proxy password was accepted")
	}
	lan.ProxyPassword = "0123456789abcdef01234567"
	if err := lan.Validate(); err != nil {
		t.Fatalf("valid LAN settings rejected: %v", err)
	}
	user, pass, ok := lan.ProxyAuth()
	if !ok || user != ProxyUsernameDefault || pass != lan.ProxyPassword {
		t.Fatalf("ProxyAuth = %q %q %v", user, pass, ok)
	}

	loop := DefaultSettings()
	if err := loop.Validate(); err != nil {
		t.Fatalf("default settings rejected: %v", err)
	}
	if loop.AuthRequired() {
		t.Fatal("a loopback listener must not require authentication")
	}
	if _, _, ok := loop.ProxyAuth(); ok {
		t.Fatal("a loopback listener must not hand out credentials")
	}
}

func TestNewProxyPassword(t *testing.T) {
	seen := make(map[string]bool, 32)
	for i := 0; i < 32; i++ {
		p := NewProxyPassword()
		if len(p) != 24 {
			t.Fatalf("password length = %d, want 24", len(p))
		}
		if seen[p] {
			t.Fatalf("password repeated: %s", p)
		}
		seen[p] = true
	}
}
