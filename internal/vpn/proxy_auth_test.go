package vpn

import (
	"testing"

	"github.com/ehzyil/connect-hub/internal/model"
)

func TestSettingsProxyAuth(t *testing.T) {
	loop := model.DefaultSettings()
	if auth := settingsProxyAuth(loop); auth != nil {
		t.Fatalf("loopback listener got credentials: %+v", auth)
	}

	lan := model.DefaultSettings()
	lan.ListenHost = "0.0.0.0"
	lan.ProxyUsername = "hub"
	lan.ProxyPassword = "0123456789abcdef01234567"
	auth := settingsProxyAuth(lan)
	if auth == nil || auth.Username != "hub" || auth.Credential != lan.ProxyPassword {
		t.Fatalf("LAN listener auth = %+v", auth)
	}

	// An empty username falls back to the generated default.
	lan.ProxyUsername = ""
	if auth := settingsProxyAuth(lan); auth == nil || auth.Username != model.ProxyUsernameDefault {
		t.Fatalf("default username not applied: %+v", auth)
	}

	// Without a password there is nothing to ask for; Settings.Validate is what
	// refuses that configuration and loading falls back to loopback.
	lan.ProxyPassword = ""
	if auth := settingsProxyAuth(lan); auth != nil {
		t.Fatalf("credential without a password: %+v", auth)
	}
}
