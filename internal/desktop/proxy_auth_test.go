package desktop

import (
	"testing"

	"github.com/ehzyil/connect-hub/internal/model"
)

// Turning the listener into a LAN one must produce credentials instead of an
// open relay, and going back to loopback must stop requiring them.
func TestSettingsGenerateLANProxyCredentials(t *testing.T) {
	a := testApp(t)
	a.openSettings()
	// Never bind a real wildcard port from a test.
	a.settings.aggregate = false
	a.settings.host = "0.0.0.0"
	a.saveSettings()
	if a.settings.err != "" {
		t.Fatalf("saveSettings: %s", a.settings.err)
	}
	cfg := a.store.Config()
	if cfg.Settings.ListenHost != "0.0.0.0" {
		t.Fatalf("listen host = %q", cfg.Settings.ListenHost)
	}
	if len(cfg.Settings.ProxyPassword) != 24 {
		t.Fatalf("generated password = %q", cfg.Settings.ProxyPassword)
	}
	if cfg.Settings.ProxyUsername != model.ProxyUsernameDefault {
		t.Fatalf("username = %q", cfg.Settings.ProxyUsername)
	}
	if user, pass, ok := cfg.Settings.ProxyAuth(); !ok || user != model.ProxyUsernameDefault || pass == "" {
		t.Fatalf("ProxyAuth = %q %q %v", user, pass, ok)
	}

	// Back to loopback: no credentials required, but the generated password is
	// kept so switching LAN access on again is one click.
	a.settings.host = "127.0.0.1"
	a.saveSettings()
	cfg = a.store.Config()
	if cfg.Settings.AuthRequired() {
		t.Fatal("a loopback listener still requires credentials")
	}
	if cfg.Settings.ProxyPassword == "" {
		t.Fatal("returning to loopback wiped the stored password")
	}
}

// A password below the LAN rule is refused instead of weakening the listener,
// and nothing of the rejected draft reaches the store.
func TestSettingsRejectShortLANPassword(t *testing.T) {
	a := testApp(t)
	a.openSettings()
	a.settings.aggregate = false
	a.settings.host = "0.0.0.0"
	a.settings.proxyPass = "short"
	a.saveSettings()
	if a.settings.err == "" {
		t.Fatal("a short proxy password was accepted")
	}
	if got := a.store.Config().Settings.ListenHost; got != "127.0.0.1" {
		t.Fatalf("rejected settings leaked to the store: listen host = %q", got)
	}
}
