//go:build darwin

package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestSanitizeBypassDomains(t *testing.T) {
	input := []string{
		"127.0.0.1",
		"192.168.0.0/16",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"localhost",
		"*.local",
		"*.crashlytics.com",
		"<local>",
	}

	cleaned := sanitizeBypassDomains(input)

	// Must NOT contain any private IP range
	for _, entry := range cleaned {
		if strings.Contains(entry, "192.168.") || strings.Contains(entry, "10.0.0.0") || strings.Contains(entry, "172.16.") {
			t.Errorf("cleaned list contains private entry: %s", entry)
		}
	}

	// Must preserve normal domain and loopback
	wantEntries := []string{"127.0.0.1", "localhost", "*.local", "*.crashlytics.com", "<local>"}
	for _, want := range wantEntries {
		found := false
		for _, c := range cleaned {
			if c == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing preserved entry: %s in %v", want, cleaned)
		}
	}
}

func TestSanitizeBypassDomainsEmpty(t *testing.T) {
	cleaned := sanitizeBypassDomains(nil)
	want := []string{"127.0.0.1", "localhost", "*.local"}
	if !reflect.DeepEqual(cleaned, want) {
		t.Errorf("sanitizeBypassDomains(nil) = %v, want %v", cleaned, want)
	}
}

func TestFormatBypassCmd(t *testing.T) {
	cmdEmpty := formatBypassCmd("Wi-Fi", nil)
	if cmdEmpty != "networksetup -setproxybypassdomains 'Wi-Fi' 'Empty'\n" {
		t.Errorf("unexpected cmdEmpty: %s", cmdEmpty)
	}

	cmdMulti := formatBypassCmd("DEMO Mobile Boardband", []string{"127.0.0.1", "localhost", "*.local"})
	expected := "networksetup -setproxybypassdomains 'DEMO Mobile Boardband' '127.0.0.1' 'localhost' '*.local'\n"
	if cmdMulti != expected {
		t.Errorf("unexpected cmdMulti:\ngot:  %s\nwant: %s", cmdMulti, expected)
	}
}
