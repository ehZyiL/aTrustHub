package model

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func relayShareID() string {
	b := make([]byte, ShareIDBytes)
	for i := range b {
		b[i] = byte('a' + i%26)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func relayPoint() AccessPoint {
	return AccessPoint{
		ID:       "r1",
		Name:     "同事分享",
		Protocol: ProtocolLANRelay,
		Server:   "192.168.1.50",
		Port:     23456,
		Relay: &RelayPointOptions{
			Version: 1, ShareID: relayShareID(), CertificateSHA256: strings.Repeat("ab", 32),
		},
	}
}

func TestRelayPointNormalizeSkipsVPNLogin(t *testing.T) {
	p := relayPoint()
	p.SocksPort = 1081
	p.AuthMode = string(AuthModeWeCom)
	p.Username = "someone"
	p.LoginDomain = "Radius"
	p.Monitor = boolPtr(true)
	p.Normalize()
	if p.AuthMode != "" {
		t.Fatalf("relay node kept an auth mode: %q", p.AuthMode)
	}
	if p.LoginDomain != "" || p.Username != "" {
		t.Fatalf("relay node kept VPN login fields: %+v", p)
	}
	if p.SocksPort != 0 {
		t.Fatalf("relay node took a SOCKS port: %d", p.SocksPort)
	}
	if p.Monitor != nil {
		t.Fatal("relay node kept session monitoring")
	}
	if p.Port != 23456 {
		t.Fatalf("relay port was rewritten: %d", p.Port)
	}
}

func TestRelayPointValidation(t *testing.T) {
	good := relayPoint()
	if err := good.Validate(); err != nil {
		t.Fatalf("valid relay point rejected: %v", err)
	}

	bad := []func(*AccessPoint){
		func(p *AccessPoint) { p.Server = "8.8.8.8" },
		func(p *AccessPoint) { p.Server = "127.0.0.1" },
		func(p *AccessPoint) { p.Server = "nas.local" },
		func(p *AccessPoint) { p.Port = 0 },
		func(p *AccessPoint) { p.Relay = nil },
		func(p *AccessPoint) { p.Relay.Version = 3 },
		func(p *AccessPoint) { p.Relay.ShareID = "short" },
		func(p *AccessPoint) { p.Relay.CertificateSHA256 = "abc" },
	}
	for i, mutate := range bad {
		p := relayPoint()
		mutate(&p)
		if err := p.Validate(); err == nil {
			t.Fatalf("case %d: invalid relay point accepted: %+v", i, p)
		}
	}

	// Relay metadata on a normal gateway must be refused instead of ignored.
	aTrust := AccessPoint{ID: "a", Name: "x", Protocol: ProtocolATrust, Server: "vpn.example.com", Port: 443, Username: "u", InPool: true, Relay: &RelayPointOptions{Version: 1}}
	if err := aTrust.Validate(); err == nil {
		t.Fatal("non-relay point accepted relay metadata")
	}
	// An unknown protocol is refused.
	unknown := relayPoint()
	unknown.Protocol = "wireguard"
	if err := unknown.Validate(); err == nil {
		t.Fatal("unknown protocol accepted")
	}
}

func TestRelayLANShareDefaultsOff(t *testing.T) {
	var s Settings
	s.Normalize()
	if s.LANShare.Enabled {
		t.Fatal("default settings enabled the share")
	}
	if s.RelayClipboardDetection {
		t.Fatal("default settings enabled clipboard detection")
	}

	// A configuration that only sets clipboard detection must keep that value
	// instead of being replaced wholesale by defaults.
	var only Settings
	only.RelayClipboardDetection = true
	only.Normalize()
	if !only.RelayClipboardDetection {
		t.Fatal("Normalize reset an explicit clipboard preference")
	}

	// Upgraded configuration: nothing stored means off.
	var cfg Config
	if err := json.Unmarshal([]byte(`{"version":1,"settings":{"listenHost":"127.0.0.1"},"points":[]}`), &cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Normalize()
	if cfg.Settings.LANShare.Enabled {
		t.Fatal("an upgraded configuration enabled the share")
	}
}

// TestNormalizeKeepsAnExplicitShareIntent guards the zero-value shortcut: a
// Settings whose only field is the share intent must not be replaced wholesale by
// defaults, which would silently switch an enabled share off.
func TestNormalizeKeepsAnExplicitShareIntent(t *testing.T) {
	var s Settings
	s.LANShare = LANShareSettings{
		Enabled: true, PointID: "a1", PreferredIPv4: "192.168.1.50",
		BoundPort: 23456, ShareID: relayShareID(), CertificateSHA256: strings.Repeat("ab", 32),
	}
	s.Normalize()
	if !s.LANShare.Enabled || s.LANShare.BoundPort != 23456 || s.LANShare.ShareID == "" {
		t.Fatalf("an explicit share intent was normalised away: %+v", s.LANShare)
	}
	if s.ListenHost == "" {
		t.Fatal("normalising a share-only settings left the other defaults empty")
	}
}

func TestRelayCloneDeepCopiesMetadata(t *testing.T) {
	cfg := Config{Points: []AccessPoint{relayPoint()}}
	clone := cfg.Clone()
	clone.Points[0].Relay.ShareID = "changed"
	if cfg.Points[0].Relay.ShareID == "changed" {
		t.Fatal("Clone shared the relay metadata pointer")
	}
}

func TestRelayPointConfigRoundTrip(t *testing.T) {
	cfg := Config{Version: CurrentVersion, Settings: DefaultSettings(), Points: []AccessPoint{relayPoint()}}
	cfg.Normalize()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var back Config
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	back.Normalize()
	if back.Points[0].Relay == nil || back.Points[0].Relay.ShareID != cfg.Points[0].Relay.ShareID {
		t.Fatal("relay identity lost in the configuration round trip")
	}
}

func TestAddRelayPointKeepsSocksPortZero(t *testing.T) {
	cfg := Config{Settings: DefaultSettings()}
	cfg.Normalize()
	before := cfg.Settings.AggregatePort
	p := cfg.Add(relayPoint())
	if p.SocksPort != 0 {
		t.Fatalf("Add gave a relay node SOCKS port %d", p.SocksPort)
	}
	if cfg.Settings.AggregatePort != before {
		t.Fatal("Add changed the aggregate port")
	}
}

func TestValidShareID(t *testing.T) {
	if !ValidShareID(relayShareID()) {
		t.Fatal("generated share ID rejected")
	}
	for _, bad := range []string{"", "short", relayShareID() + "=", strings.Repeat("A", 21), strings.Repeat("A", 23), "%%%invalid-base64%%%"} {
		if ValidShareID(bad) {
			t.Fatalf("accepted invalid share ID %q", bad)
		}
	}
}

func boolPtr(v bool) *bool { return &v }
