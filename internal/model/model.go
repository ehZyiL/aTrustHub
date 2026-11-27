// Package model holds the configuration of the app: the aTrust access
// points it logs in to and the settings of the proxies it serves.
package model

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ehzyil/connect-hub/internal/lanname"
	"github.com/ehzyil/connect-hub/internal/routing"
)

// Routing is how the aggregate proxy picks the access point a new
// connection goes through.
type Routing string

const (
	// RoutingLatency sends a connection through the online access point
	// with the lowest recent dial latency.
	RoutingLatency Routing = "latency"
	// RoutingRoundRobin spreads connections over the online access points.
	RoutingRoundRobin Routing = "round_robin"
	// RoutingFailover uses the first online access point, in the order of
	// the list, and moves to the next one only when it fails.
	RoutingFailover Routing = "failover"
	// RoutingHash keeps one destination on one access point, by hashing
	// its host name.
	RoutingHash Routing = "hash"
)

// Routing values as the UI shows them.
var RoutingLabels = []struct {
	Value Routing
	Label string
}{
	{RoutingLatency, "延迟优先"},
	{RoutingRoundRobin, "轮询"},
	{RoutingFailover, "故障转移"},
	{RoutingHash, "按域名固定"},
}

// Label returns the Chinese name of the routing mode.
func (r Routing) Label() string {
	for _, entry := range RoutingLabels {
		if entry.Value == r {
			return entry.Label
		}
	}
	return string(r)
}

// Valid reports whether r is one of the modes.
func (r Routing) Valid() bool {
	for _, entry := range RoutingLabels {
		if entry.Value == r {
			return true
		}
	}
	return false
}

// AuthMode is how an access point authenticates.
type AuthMode string

const (
	// AuthModeAuto is the old "let the server decide" mode. The editor no
	// longer offers it; it stays so points saved by an older version keep
	// logging in the way they used to.
	AuthModeAuto AuthMode = "auto"
	// AuthModePassword is aTrust's username and password login
	// (auth/psw), optionally with a TOTP secret. It logs in by itself.
	AuthModePassword AuthMode = "psw"
	// AuthModeWeCom is an external login, such as the WeCom QR code the
	// official client shows (auth/httpsOauth2 or auth/qywechat). It is
	// completed in the app's own popup.
	AuthModeWeCom AuthMode = "wecom"
	// AuthModeSSO is a third-party single sign-on portal (auth/cas and
	// friends) that only finishes in a real browser; the session the browser
	// leaves behind is what the tunnel resumes.
	AuthModeSSO AuthMode = "sso"
)

// AuthModeLabels are the modes the editor offers, in display order.
// AuthModeAuto is deliberately absent: the login flow now follows the
// configuration instead of a "detect it yourself" choice.
var AuthModeLabels = []struct {
	Value AuthMode
	Label string
}{
	{AuthModePassword, "账号密码"},
	{AuthModeWeCom, "企业微信"},
	{AuthModeSSO, "单点登录"},
}

// Label returns the Chinese name of the mode.
func (m AuthMode) Label() string {
	for _, entry := range AuthModeLabels {
		if entry.Value == m {
			return entry.Label
		}
	}
	if m == AuthModeAuto {
		// Legacy value: still shown for points saved before the mode was
		// dropped from the editor.
		return "自动识别（旧）"
	}
	return string(m)
}

// Valid reports whether m is a mode this version understands. AuthModeAuto
// stays valid so an old configuration is not rewritten behind the user's
// back; the editor simply no longer offers it.
func (m AuthMode) Valid() bool {
	return m == AuthModeAuto || m == AuthModePassword || m == AuthModeWeCom || m == AuthModeSSO
}

// AccessPoint is one aTrust server the app logs in to. Its cred and
// TOTP secret live in the secret store, under the point's ID, not here.
const (
	ProtocolATrust      = "atrust"
	ProtocolEasyConnect = "easyconnect"
	// ProtocolLANRelay is a node imported from a colleague's share code. It has
	// no VPN login of its own: the credential in the secret store is the LAN
	// share token, and the tunnel runs through the sharing host.
	ProtocolLANRelay = "lan_relay"
)

// RelayPointOptions is the LAN-share identity a relay node was imported from.
// It is metadata only: the token stays in the secret store and the rules come
// from the sharing host after authentication.
type RelayPointOptions struct {
	PairingUnconfirmed bool   `json:"pairingUnconfirmed,omitempty"`
	Version            int    `json:"version"`
	ShareID            string `json:"shareId"`
	CertificateSHA256  string `json:"certificateSHA256"`
	// HistoryInitialized records that a first verified snapshot was persisted
	// for this node. The cache itself is never an authorization source.
	HistoryInitialized bool `json:"historyInitialized,omitempty"`
}

// IsRelay reports whether the point is a LAN-share node.
func (p *AccessPoint) IsRelay() bool { return p.Protocol == ProtocolLANRelay }

type AccessPoint struct {
	Protocol        string   `json:"protocol,omitempty"`
	RemoteDNS       string   `json:"remoteDNS,omitempty"`
	InternalDomains []string `json:"internalDomains,omitempty"`
	// CertificateSHA256 pins the gateway leaf certificate, and it is enforced by
	// the EasyConnect worker only (pinnedcert). aTrust has no enforcement point
	// yet, so a pin stored on an aTrust point is accepted and ignored; keep it
	// that way only until aTrust gains one.
	CertificateSHA256 string `json:"certificateSHA256,omitempty"`
	HealthTarget      string `json:"healthTarget,omitempty"`

	ID       string `json:"id"`
	Name     string `json:"name"`
	Server   string `json:"server"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	// AuthMode is "psw", "wecom" or "sso"; empty means "psw". The old
	// "auto" value is still accepted but no longer offered.
	AuthMode    string `json:"authMode,omitempty"`
	LoginDomain string `json:"loginDomain,omitempty"`
	// SocksPort is the SOCKS5 port this access point serves on its own;
	// 0 disables it.
	SocksPort   int  `json:"socksPort"`
	InPool      bool `json:"inPool"`
	AutoConnect bool `json:"autoConnect"`
	// LoginInBrowser asks the login window to hand the page to the system
	// browser and take the callback address back by paste. Some SSO portals
	// only finish their login in a real browser.
	LoginInBrowser bool  `json:"loginInBrowser,omitempty"`
	CreatedAt      int64 `json:"createdAt,omitempty"`
	// Monitor asks the portal now and then whether this access point's login
	// is still the active one: another client signing in with the same account
	// takes the session over, and the tunnel can look fine while it is dead.
	// nil means the default, which is on.
	Monitor *bool `json:"monitor,omitempty"`
	// MonitorInterval is the check period in seconds; 0 means the default.
	MonitorInterval int `json:"monitorInterval,omitempty"`
	// DisabledApps holds application IDs the user took out of the tunnel,
	// because their addresses clash with the local network or with another
	// access point.
	DisabledApps []string `json:"disabledApps,omitempty"`
	// Relay is set on ProtocolLANRelay points only. It names the share the node
	// was imported from, so the same sharing host can be recognised again.
	Relay *RelayPointOptions `json:"relay,omitempty"`
}

// LANShareSettings is A's persisted 局域网分享 intent and bound address. Only
// Enabled is a user intent; Running is runtime state and never stored. The
// absence of the whole object means "never enabled", so a first install and an
// upgraded configuration both start switched off.
type LANShareSettings struct {
	Paused  bool `json:"paused,omitempty"`
	Enabled bool `json:"enabled"`
	// PointID is the single access point shared by this host. Nothing else is
	// scoped: the whole point is shared.
	PointID string `json:"pointId,omitempty"`
	// InterfaceName is a hint only; every start re-reads the interface and
	// refuses to bind an address it cannot currently prove is up.
	InterfaceName string `json:"interfaceName,omitempty"`
	PreferredIPv4 string `json:"preferredIPv4,omitempty"`
	// Port is the requested port; 0 means the kernel picks one on first enable.
	Port int `json:"port,omitempty"`
	// BoundPort is the port that actually bound, reused verbatim on restore so
	// a printed share code keeps working.
	BoundPort int `json:"boundPort,omitempty"`
	// ShareID and CertificateSHA256 identify the persisted sharing identity.
	ShareID           string `json:"shareId,omitempty"`
	CertificateSHA256 string `json:"certificateSHA256,omitempty"`
	// DiscoveryEnabled lets colleagues on the same network find this share over
	// DNS-SD. It is a pointer on purpose: nil means "the user never chose",
	// which is the state of every configuration written before discovery
	// existed. Discovery never turns sharing on, and a nil value is never
	// rewritten to true by Normalize or by the restore path.
	DiscoveryEnabled *bool `json:"discoveryEnabled,omitempty"`
	// DiscoveryName is the public alias broadcast on the LAN. Empty means the
	// default derived from the share ID; it never falls back to the VPN point
	// name, the account or the computer name.
	DiscoveryName string `json:"discoveryName,omitempty"`
}

// IsZero reports whether no field carries a value. It replaces comparing the
// struct with a zero literal: with a pointer field that comparison still
// compiles but a configuration holding only discovery=false would stop looking
// empty and would silently skip Settings.Normalize's default backfill.
func (s LANShareSettings) IsZero() bool {
	return s.Enabled == false && !s.Paused && s.PointID == "" && s.InterfaceName == "" &&
		s.PreferredIPv4 == "" && s.Port == 0 && s.BoundPort == 0 &&
		s.ShareID == "" && s.CertificateSHA256 == "" &&
		s.DiscoveryEnabled == nil && s.DiscoveryName == ""
}

// ShareIDBytes is the size of a share identity, Base64URL-encoded without
// padding into 22 characters.
const ShareIDBytes = 16

// ShareTokenBytes is the size of the share and client-session tokens.
const ShareTokenBytes = 32

// ValidShareID reports whether s is a well-formed v1 share identity.
func ValidShareID(s string) bool {
	b, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && len(b) == ShareIDBytes
}

// DiscoveryNameMaxRunes and DiscoveryNameMaxBytes mirror the rules in
// internal/lanname, which every boundary uses.
const (
	DiscoveryNameMaxRunes = lanname.MaxRunes
	DiscoveryNameMaxBytes = lanname.MaxBytes
)

// ValidDiscoveryName checks a public alias; see internal/lanname.
func ValidDiscoveryName(name string) error { return lanname.Valid(name) }

// DefaultDiscoveryName is the alias used when the user did not type one.
func DefaultDiscoveryName(shareID string) string { return lanname.Default(shareID) }

// ValidShareToken reports whether s is a well-formed v1 bearer token.
func ValidShareToken(s string) bool {
	b, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && len(b) == ShareTokenBytes
}

// SHA256Hex is the canonical 64-character lowercase form of a certificate
// fingerprint.
func SHA256Hex(sum []byte) string { return hex.EncodeToString(sum) }

// NewShareID returns a new random share identity. Randomness failure is fatal
// for the caller: a share must never fall back to a clock-derived secret.
func NewShareID() (string, error) {
	b := make([]byte, ShareIDBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// NewShareToken returns a new random share or client-session token.
func NewShareToken() (string, error) {
	b := make([]byte, ShareTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// RFC1918 reports whether ip is a private-use IPv4 unicast address. The LAN
// share listener is limited to these; loopback, unspecified, multicast and
// public addresses are rejected.
func RFC1918(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	return v4[0] == 10 || (v4[0] == 172 && v4[1]&0xf0 == 16) || (v4[0] == 192 && v4[1] == 168)
}

// defaultMonitorInterval is how often the session is probed when unset.
const defaultMonitorInterval = 300

// MonitorEnabled reports whether session validity monitoring is on. Existing
// configurations have no value stored, and those default to on.
func (p *AccessPoint) MonitorEnabled() bool {
	if p.Monitor == nil {
		return true
	}
	return *p.Monitor
}

// MonitorIntervalSeconds is the probe period, with the default applied and a
// floor so a typo cannot turn the app into a request flood.
func (p *AccessPoint) MonitorIntervalSeconds() int {
	if p.MonitorInterval <= 0 {
		return defaultMonitorInterval
	}
	if p.MonitorInterval < 30 {
		return 30
	}
	return p.MonitorInterval
}
func (p *AccessPoint) AppDisabled(id string) bool {
	for _, s := range p.DisabledApps {
		if s == id {
			return true
		}
	}
	return false
}

// SetAppDisabled records the choice and reports whether it changed anything.
func (p *AccessPoint) SetAppDisabled(id string, disabled bool) bool {
	if id == "" {
		return false
	}
	if p.AppDisabled(id) == disabled {
		return false
	}
	kept := make([]string, 0, len(p.DisabledApps)+1)
	for _, s := range p.DisabledApps {
		if s != id {
			kept = append(kept, s)
		}
	}
	if disabled {
		kept = append(kept, id)
	}
	p.DisabledApps = kept
	return true
}

// Settings are the app's own settings.
type Settings struct {
	// ListenHost is the address both the per-access-point and the
	// aggregate proxies bind to. Loopback by default.
	ListenHost string `json:"listenHost"`
	// ProxyUsername / ProxyPassword guard the listeners when ListenHost is not
	// loopback. A loopback listener stays unauthenticated so existing browser
	// and tool configuration keeps working; exposing the proxy to the LAN is a
	// deliberate act and requires these credentials.
	ProxyUsername    string               `json:"proxyUsername,omitempty"`
	ProxyPassword    string               `json:"proxyPassword,omitempty"`
	AggregatePort    int                  `json:"aggregatePort"`
	AggregateEnabled bool                 `json:"aggregateEnabled"`
	Routing          Routing              `json:"routing"`
	SharedExits      []routing.Group      `json:"sharedExits,omitempty"`
	RoutePolicies    []routing.Policy     `json:"routePolicies,omitempty"`
	DNSBindings      []routing.DNSBinding `json:"dnsBindings,omitempty"`
	DialTimeoutMS    int                  `json:"dialTimeoutMs,omitempty"`
	TotalTimeoutMS   int                  `json:"totalTimeoutMs,omitempty"`
	// HealthIntervalSec is how often an online access point is probed
	// through its tunnel; 0 disables probing.
	HealthIntervalSec int  `json:"healthIntervalSec"`
	AutoReconnect     bool `json:"autoReconnect"`
	// Appearance is the window colour mode: "system" follows the desktop,
	// "light" and "dark" pin it. Empty means "system".
	Appearance string `json:"appearance,omitempty"`
	// Theme is the colour family: "blue" (default), "green", or "purple".
	// Each family ships a light and a dark version.
	Theme string `json:"theme,omitempty"`
	// QuitOnClose 为 true 时，点窗口关闭按钮彻底退出（仅 Windows 可见）；
	// 否则关闭只是隐藏到托盘。
	QuitOnClose bool `json:"quitOnClose,omitempty"`
	// SecretStore is where access point passwords are kept: "file" for the
	// local 0600 secrets.json, or "keychain" for the macOS Keychain. It is
	// read at startup, so a change takes effect after a restart.
	SecretStore string `json:"secretStore"`
	// TunEnabled remembers whether global TUN was on, and TunPointID which
	// access point it used, so the switch reflects the last state.
	TunEnabled bool   `json:"tunEnabled"`
	TunPointID string `json:"tunPointID"`
	// HideDock keeps the app out of the Dock (macOS), with a menu bar icon
	// instead, so closing the window leaves it running.
	HideDock bool `json:"hideDock"`
	// CaptureMode 是记住的接管方式（见 CaptureMode* 常量）：启动后按它恢复。
	// 首次运行默认为系统代理；用 id 而不是界面文案，改文案不会让设置失效。
	CaptureMode string `json:"captureMode,omitempty"`
	// SimpleMode 把界面收敛成「一个接入点 + 一个网址输入框」，专业设置收进设置页。
	// 它只影响展示与默认值（见 ConvergeSimple），不改变任何业务逻辑。
	// 默认开启（见 DefaultSettings）。已经存在的完整模式配置不会被迁移过来：
	// Normalize 只在整份设置都是零值时才回落到默认值，带着其他字段的旧配置保持原样。
	SimpleMode bool `json:"simpleMode,omitempty"`
	// AutoRestoreAppCapture 是「启动/登录后自动恢复应用接管」的意图。
	// CaptureMode 记的是上次真正生效的档位；这个字段记的是用户是否希望
	// 在条件满足时自动把它重新打开。默认关闭，不改变旧配置行为。
	AutoRestoreAppCapture bool `json:"autoRestoreAppCapture,omitempty"`
	// AutoLoginOptIn records that the user has been offered the auto-login
	// default. Access points do not log in at startup unless they ask for it.
	AutoLoginOptIn bool `json:"autoLoginOptIn"`
	// AutoCheckUpdate 开启后启动时及每天自动检查一次更新，并在状态栏提示新版本。
	AutoCheckUpdate bool `json:"autoCheckUpdate"`
	// LANShare is A's 局域网分享 enable intent. Its zero value is "off", which is
	// what a first install and an upgraded configuration get.
	LANShare LANShareSettings `json:"lanShare,omitempty"`
	// RelayClipboardDetection watches the clipboard for share codes. It is off
	// by default and reads nothing until the user turns it on.
	RelayClipboardDetection bool `json:"relayClipboardDetection,omitempty"`
}

// Secret store choices.
const (
	SecretStoreFile     = "file"
	SecretStoreKeychain = "keychain"
)

// CaptureMode values are the remembered 接管方式. They are persisted, so they
// never carry UI copy: the labels may change without resetting the setting.
const (
	CaptureModeOff    = "off"
	CaptureModeSystem = "system"
	CaptureModeTUN    = "tun"
	CaptureModeApp    = "app"
)

// Config is the file the app keeps its configuration in.
type Config struct {
	Version   int           `json:"version"`
	Settings  Settings      `json:"settings"`
	Points    []AccessPoint `json:"points"`
	LocalApps []LocalApp    `json:"localApps,omitempty"`
}

// CurrentVersion is the version of the configuration format.
const CurrentVersion = 1

// DefaultSettings returns the settings of a first run.
//
// 首次运行默认进简单模式：首屏只有一张连接卡和一个网址输入框。它是展示层的
// 默认收敛，不是功能阉割——设置页里一个开关就能回到完整模式（见 SimpleMode）。
func DefaultSettings() Settings {
	return Settings{
		ListenHost:        "127.0.0.1",
		AggregatePort:     1080,
		AggregateEnabled:  true,
		Routing:           RoutingLatency,
		DialTimeoutMS:     5000,
		TotalTimeoutMS:    15000,
		HealthIntervalSec: 60,
		AutoReconnect:     true,
		SecretStore:       SecretStoreKeychain,
		CaptureMode:       CaptureModeSystem,
		SimpleMode:        true,
		AutoCheckUpdate:   true,
	}
}

// ProxyUsernameDefault is the account name generated for LAN listeners.
const ProxyUsernameDefault = "hub"

// MinProxyPasswordLen is the shortest proxy password a LAN listener accepts. The
// generated one is 24 characters; this floor only rejects hand-edited values.
const MinProxyPasswordLen = 12

// IsLoopbackHost reports whether host only addresses this machine. An empty
// value is not loopback: it would bind every interface.
func IsLoopbackHost(host string) bool {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// AuthRequired reports whether the local listeners must ask for credentials.
// Loopback never does, so upgrading must not break existing configurations.
func (s Settings) AuthRequired() bool { return !IsLoopbackHost(s.ListenHost) }

// ProxyAuth is the credential pair the listeners ask for, and ok is false when
// the listener may stay open (loopback, or a configuration that has not been
// validated yet).
func (s Settings) ProxyAuth() (user, pass string, ok bool) {
	if !s.AuthRequired() || strings.TrimSpace(s.ProxyPassword) == "" {
		return "", "", false
	}
	user = strings.TrimSpace(s.ProxyUsername)
	if user == "" {
		user = ProxyUsernameDefault
	}
	return user, s.ProxyPassword, true
}

// NewProxyPassword returns a 24-character password for a LAN listener.
func NewProxyPassword() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(b[:])
}

// NewID returns a random access point ID.
func NewID() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand does not fail in practice; fall back to the clock
		// rather than taking the app down.
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(b[:])
}

// Normalize fills defaults and cleans the user's input, so that the rest
// of the app can rely on the fields.
func (c *Config) Normalize() {
	if c.Version == 0 {
		c.Version = CurrentVersion
	}
	c.Settings.Normalize()
	seen := map[string]bool{}
	for i := range c.Points {
		p := &c.Points[i]
		p.Normalize()
		if p.ID == "" || seen[p.ID] {
			p.ID = NewID()
		}
		seen[p.ID] = true
	}
	seenApps := map[string]bool{}
	for i := range c.LocalApps {
		app := &c.LocalApps[i]
		app.Normalize()
		if app.ID == "" || seenApps[app.ID] {
			app.ID = NewID()
		}
		seenApps[app.ID] = true
	}
	c.EnsurePorts()
}

// Normalize fills the default settings.
func (s *Settings) Normalize() {
	// 整份设置都是零值 = 还没人做过选择，直接给默认值（现已包含简单模式）。
	// 已知副作用（接受）：手写的最小配置 {"settings":{"simpleMode":false}} 也会
	// 回到默认值，因为 omitempty 的 bool 分不出“没选”和“选了 false”。真实用户
	// 不受影响：应用自己写出的配置总带着其它字段，不会命中这个早退分支。
	if s.ListenHost == "" && s.AggregatePort == 0 && s.Routing == "" &&
		s.HealthIntervalSec == 0 && !s.AggregateEnabled && !s.AutoReconnect && len(s.SharedExits) == 0 && len(s.RoutePolicies) == 0 && len(s.DNSBindings) == 0 && s.DialTimeoutMS == 0 && s.TotalTimeoutMS == 0 && s.CaptureMode == "" && !s.SimpleMode && !s.AutoRestoreAppCapture && !s.AutoCheckUpdate &&
		!s.RelayClipboardDetection && s.LANShare.IsZero() {
		*s = DefaultSettings()
		return
	}
	d := DefaultSettings()
	if s.DialTimeoutMS <= 0 {
		s.DialTimeoutMS = d.DialTimeoutMS
	}
	if s.TotalTimeoutMS <= 0 {
		s.TotalTimeoutMS = d.TotalTimeoutMS
	}
	if strings.TrimSpace(s.ListenHost) == "" {
		s.ListenHost = d.ListenHost
	}
	// A listener bound to one interface is written as a bare IP (or ::1).
	s.ListenHost = strings.TrimSpace(strings.Trim(s.ListenHost, "[]"))
	s.ProxyUsername = strings.TrimSpace(s.ProxyUsername)
	s.ProxyPassword = strings.TrimSpace(s.ProxyPassword)
	if s.AggregatePort <= 0 || s.AggregatePort > 65535 {
		s.AggregatePort = d.AggregatePort
	}
	if !s.Routing.Valid() {
		s.Routing = d.Routing
	}
	if s.HealthIntervalSec < 0 {
		s.HealthIntervalSec = 0
	}
	// 颜色模式只认三档，旧配置里的空值或其他值一律归到跟随系统。
	switch s.Appearance {
	case "light", "dark", "system":
	default:
		s.Appearance = "system"
	}
	// 主题色系同样只认三套，空值与脏值归到默认的经典蓝白。
	switch s.Theme {
	case "blue", "green", "purple":
	default:
		s.Theme = "blue"
	}
	// 接管方式只认四种 id；空值与脏值归到默认的系统代理，
	// 否则一个手改坏的字段会静默把接管关掉。
	switch s.CaptureMode {
	case CaptureModeOff, CaptureModeSystem, CaptureModeTUN, CaptureModeApp:
	default:
		s.CaptureMode = d.CaptureMode
	}
	s.LANShare.Normalize()
}

// Normalize cleans the share intent. It never turns a share on: the only path
// that sets Enabled is the user pressing 开启共享.
func (s *LANShareSettings) Normalize() {
	s.PointID = strings.TrimSpace(s.PointID)
	s.InterfaceName = strings.TrimSpace(s.InterfaceName)
	s.PreferredIPv4 = strings.TrimSpace(strings.Trim(s.PreferredIPv4, "[]"))
	s.ShareID = strings.TrimSpace(s.ShareID)
	s.CertificateSHA256 = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s.CertificateSHA256), ":", ""))
	if s.Port < 0 || s.Port > 65535 {
		s.Port = 0
	}
	if s.BoundPort < 1 || s.BoundPort > 65535 {
		s.BoundPort = 0
	}
	if s.PreferredIPv4 != "" && !RFC1918(net.ParseIP(s.PreferredIPv4)) {
		s.PreferredIPv4 = ""
	}
	// A public alias that cannot be broadcast is dropped rather than repaired
	// into something the user did not choose: the default applies instead.
	if s.DiscoveryName = strings.TrimSpace(s.DiscoveryName); s.DiscoveryName != "" {
		if err := ValidDiscoveryName(s.DiscoveryName); err != nil {
			s.DiscoveryName = ""
		}
	}
}

// Normalize cleans one access point.
func (p *AccessPoint) Normalize() {
	if p.Protocol == "" {
		p.Protocol = ProtocolATrust
	}
	p.RemoteDNS = strings.TrimSpace(p.RemoteDNS)
	p.HealthTarget = strings.TrimSpace(p.HealthTarget)
	p.CertificateSHA256 = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(p.CertificateSHA256), ":", ""))
	for i, domain := range p.InternalDomains {
		p.InternalDomains[i] = strings.Trim(strings.ToLower(strings.TrimSpace(domain)), ".")
	}

	p.Server = CleanServer(p.Server)
	p.Username = strings.TrimSpace(p.Username)
	if p.IsRelay() {
		// A relay node has no VPN login: no auth mode, no Radius domain, no
		// per-point SOCKS port. Emptying the login fields keeps the editor and
		// the generic validation paths from inventing a username.
		p.Username, p.LoginDomain, p.RemoteDNS = "", "", ""
		p.AuthMode = ""
		p.SocksPort = 0
		p.CertificateSHA256 = ""
		p.InternalDomains = nil
		p.Monitor = nil
		p.MonitorInterval = 0
		if p.Relay != nil {
			p.Relay.ShareID = strings.TrimSpace(p.Relay.ShareID)
			p.Relay.CertificateSHA256 = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(p.Relay.CertificateSHA256), ":", ""))
			if p.Relay.Version == 0 {
				p.Relay.Version = 1
			}
		}
	} else {
		if p.AuthMode == "" || !AuthMode(p.AuthMode).Valid() {
			// Empty has always meant "账号密码"; keep that reading now that
			// "自动识别" is gone from the editor.
			p.AuthMode = string(AuthModePassword)
		}
		if p.LoginDomain == "" && p.Protocol != ProtocolEasyConnect {
			// ZJU-Connect's aTrust default; servers list it as an auth
			// domain and the login fails without one.
			p.LoginDomain = "Radius"
		}
	}
	if p.Port == 0 && !p.IsRelay() {
		p.Port = 443
	}
	if p.Name == "" {
		p.Name = p.Server
		if p.Name == "" {
			p.Name = "未命名接入点"
		}
	}
	if p.SocksPort < 0 || p.SocksPort > 65535 {
		p.SocksPort = 0
	}
	if p.CreatedAt == 0 {
		p.CreatedAt = time.Now().Unix()
	}
}

// ParseAccessAddress turns what the aTrust client calls an access address,
// such as https://vpn.example.com:443, into the server and port the
// client needs. A missing scheme means https, a missing port means 443, and
// a path or query is ignored.
func ParseAccessAddress(raw string) (string, int, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", 0, errors.New("接入地址不能为空")
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", 0, fmt.Errorf("接入地址无效：%w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", 0, errors.New("接入地址必须是 http(s):// 开头")
	}
	if u.User != nil {
		return "", 0, errors.New("接入地址不能包含用户名")
	}
	host := u.Hostname()
	if host == "" {
		return "", 0, errors.New("接入地址缺少主机名")
	}
	port := 443
	if p := u.Port(); p != "" {
		port, err = strconv.Atoi(p)
		if err != nil || port < 1 || port > 65535 {
			return "", 0, errors.New("接入地址的端口必须在 1–65535 之间")
		}
	}
	return host, port, nil
}

// FormatAccessAddress is the inverse of ParseAccessAddress, for the editor.
func FormatAccessAddress(server string, port int) string {
	if port == 0 || port == 443 {
		host := server
		if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
			host = "[" + host + "]"
		}
		return "https://" + host
	}
	return "https://" + net.JoinHostPort(server, strconv.Itoa(port))
}

// CleanServer turns what the user typed into a bare host name: it drops a
// scheme, a path and a port, which has a field of its own.
func CleanServer(server string) string {
	s := strings.TrimSpace(server)
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	s = strings.Trim(s, "[]")
	return strings.TrimSpace(s)
}

// Validate checks what the user entered, in the words the dialog shows.
func (c *Config) Validate() error {
	if err := c.Settings.Validate(); err != nil {
		return err
	}
	for i := range c.Points {
		if err := c.Points[i].Validate(); err != nil {
			return fmt.Errorf("%s：%w", c.Points[i].Name, err)
		}
	}
	seenApps := map[string]bool{}
	for i := range c.LocalApps {
		app := &c.LocalApps[i]
		if err := app.Validate(); err != nil {
			return fmt.Errorf("%s：%w", app.Name, err)
		}
		if seenApps[app.ID] {
			return errors.New("本机软件 ID 重复")
		}
		seenApps[app.ID] = true
		if c.Find(app.PointID) == nil {
			return fmt.Errorf("%s：关联的接入点不存在，请重新选择", app.Name)
		}
	}
	return nil
}

// Validate checks the settings.
func (s *Settings) Validate() error {
	seenDNS := map[string]bool{}
	for _, b := range s.DNSBindings {
		if err := b.Validate(); err != nil {
			return err
		}
		if seenDNS[b.ID] {
			return errors.New("DNS 归属 ID 重复")
		}
		seenDNS[b.ID] = true
	}
	seenPolicies := map[string]bool{}
	for _, p := range s.RoutePolicies {
		if err := p.Validate(); err != nil {
			return err
		}
		if seenPolicies[p.ID] {
			return errors.New("路由策略 ID 重复")
		}
		seenPolicies[p.ID] = true
	}
	if s.DialTimeoutMS < 0 || s.DialTimeoutMS > 45000 || s.TotalTimeoutMS < 0 || s.TotalTimeoutMS > 120000 {
		return errors.New("拨号预算无效：单次不超过 45 秒，总计不超过 120 秒")
	}
	seenGroups := make(map[string]bool)
	for _, group := range s.SharedExits {
		if group.DNSFailover {
			if err := (routing.DNSBinding{ID: group.ID, Pattern: group.Pattern, GatewayID: "group"}).Validate(); err != nil {
				return errors.New("DNS 备用出口必须使用域名")
			}
		}
		if group.ID == "" || seenGroups[group.ID] || len(group.Gateways) < 2 || !routing.ValidPattern(group.Pattern) || group.PortMin < 1 || group.PortMax > 65535 || group.PortMax < group.PortMin || (group.Protocol != "tcp" && group.Protocol != "udp" && group.Protocol != "all") {
			return errors.New("同业务出口配置无效")
		}
		seenGroups[group.ID] = true
		seen := make(map[string]bool)
		for _, id := range group.Gateways {
			if id == "" || seen[id] {
				return errors.New("同业务出口包含空或重复网关")
			}
			seen[id] = true
		}
	}
	if s.SecretStore != SecretStoreKeychain {
		s.SecretStore = SecretStoreFile
	}
	if s.ListenHost == "" {
		return errors.New("监听地址不能为空")
	}
	if !IsLoopbackHost(s.ListenHost) {
		if net.ParseIP(strings.Trim(s.ListenHost, "[]")) == nil {
			return errors.New("监听地址必须是 IP 地址或 localhost")
		}
		// Exposing the proxy to the LAN without credentials makes it an open
		// relay for every host that can reach this machine.
		if strings.TrimSpace(s.ProxyPassword) == "" {
			return errors.New("监听地址不是本机回环时，必须设置代理密码")
		}
		if len(s.ProxyPassword) < MinProxyPasswordLen {
			return errors.New("代理密码至少 12 位")
		}
	}
	if s.AggregatePort < 1 || s.AggregatePort > 65535 {
		return errors.New("统一入口端口必须在 1–65535 之间")
	}
	if !s.Routing.Valid() {
		return errors.New("分流模式无效")
	}
	if s.HealthIntervalSec < 0 {
		return errors.New("健康检查间隔不能为负")
	}
	if s.LANShare.Enabled {
		// Enabled without a usable identity is not a validation error: it is
		// the Blocked state the controller reports, because the user may have
		// deleted the point or the secret store may be locked. Only malformed
		// values are rejected here.
		if s.LANShare.ShareID != "" && !ValidShareID(s.LANShare.ShareID) {
			return errors.New("分享 ID 格式无效")
		}
		if s.LANShare.CertificateSHA256 != "" {
			if b, err := hex.DecodeString(s.LANShare.CertificateSHA256); err != nil || len(b) != 32 || len(s.LANShare.CertificateSHA256) != 64 {
				return errors.New("分享证书指纹必须是 64 位十六进制")
			}
		}
		if s.LANShare.PreferredIPv4 != "" && !RFC1918(net.ParseIP(s.LANShare.PreferredIPv4)) {
			return errors.New("分享监听地址必须是局域网（RFC1918）地址")
		}
	}
	return nil
}

func (s Settings) Clone() Settings {
	// The discovery preference is a pointer, so a clone must not share it with
	// the caller (or with the store's snapshot).
	if s.LANShare.DiscoveryEnabled != nil {
		enabled := *s.LANShare.DiscoveryEnabled
		s.LANShare.DiscoveryEnabled = &enabled
	}
	s.DNSBindings = append([]routing.DNSBinding(nil), s.DNSBindings...)
	s.RoutePolicies = append([]routing.Policy(nil), s.RoutePolicies...)
	s.SharedExits = append([]routing.Group(nil), s.SharedExits...)
	for i := range s.SharedExits {
		s.SharedExits[i].Gateways = append([]string(nil), s.SharedExits[i].Gateways...)
	}
	return s
}

// Validate checks one access point.
func (p *AccessPoint) Validate() error {
	if p.Protocol != "" && p.Protocol != ProtocolATrust && p.Protocol != ProtocolEasyConnect && p.Protocol != ProtocolLANRelay {
		return errors.New("不支持的 VPN 协议")
	}
	if p.Protocol != ProtocolLANRelay && p.Relay != nil {
		return errors.New("只有局域网中继接入点才能带分享信息")
	}
	if p.IsRelay() {
		return p.validateRelay()
	}
	if p.Protocol == ProtocolEasyConnect && p.AuthMode != string(AuthModePassword) {
		return errors.New("EasyConnect 目前支持账号密码及后续验证码")
	}
	if p.RemoteDNS != "" && net.ParseIP(p.RemoteDNS).To4() == nil {
		return errors.New("VPN DNS 必须是 IPv4 地址")
	}
	if p.CertificateSHA256 != "" {
		b, err := hex.DecodeString(p.CertificateSHA256)
		if err != nil || len(b) != 32 {
			return errors.New("证书 SHA256 必须是 64 位十六进制指纹")
		}
	}
	for _, domain := range p.InternalDomains {
		if domain == "" || strings.ContainsAny(domain, " /:*?\\	\r\n") || net.ParseIP(domain) != nil {
			return errors.New("内网域名请填写域名后缀，用逗号分隔")
		}
	}

	if p.Server == "" {
		return errors.New("服务器地址不能为空")
	}
	if strings.ContainsAny(p.Server, " /?#") {
		return errors.New("服务器地址只能是主机名或 IP")
	}
	if p.Port < 1 || p.Port > 65535 {
		return errors.New("端口必须在 1–65535 之间")
	}
	switch AuthMode(p.AuthMode) {
	case AuthModeAuto:
		// Legacy: the server decides; a stored password makes auth/psw the
		// first choice, otherwise an external login is used.
	case AuthModeWeCom:
		// The QR login has no username; the server tells us who it is.
	case AuthModeSSO:
		// Single sign-on happens on the portal's own page, so the client
		// needs neither a username nor a password.
	default:
		if p.Username == "" {
			return errors.New("用户名不能为空")
		}
	}
	if p.SocksPort < 0 || p.SocksPort > 65535 {
		return errors.New("SOCKS5 端口必须在 0–65535 之间")
	}
	if !p.InPool && p.SocksPort == 0 {
		return errors.New("至少勾选统一入口，或填一个独立 SOCKS5 端口")
	}
	return nil
}

// validateRelay checks a LAN-share node. It never asks for a VPN login: the
// only credential is the share token, which lives in the secret store.
func (p *AccessPoint) validateRelay() error {
	ip := net.ParseIP(p.Server)
	if ip == nil || ip.To4() == nil {
		return errors.New("分享主机必须是 IPv4 地址")
	}
	if !RFC1918(ip) {
		return errors.New("分享主机必须是局域网（RFC1918）地址")
	}
	if p.Port < 1 || p.Port > 65535 {
		return errors.New("分享端口必须在 1–65535 之间")
	}
	if p.Relay == nil {
		return errors.New("缺少分享身份信息，请重新导入分享口令")
	}
	if p.Relay.Version != 1 && p.Relay.Version != 2 {
		return errors.New("分享协议版本不受支持")
	}
	if !ValidShareID(p.Relay.ShareID) {
		return errors.New("分享 ID 格式无效")
	}
	if b, err := hex.DecodeString(p.Relay.CertificateSHA256); err != nil || len(b) != 32 || len(p.Relay.CertificateSHA256) != 64 {
		return errors.New("分享证书指纹必须是 64 位十六进制")
	}
	return nil
}

// ConvergeSimple 把配置收敛成简单模式要的样子：只有一个代理地址。
//
// 它刻意不动每个接入点的 SocksPort：Manager.needsRestart 把它当成重建条件，
// 改它就会把在线的隧道拆了重登（WeCom / SSO 用户会掉回扫码）。简单模式下由
// proxyFor 忽略每点端口、统一走统一入口，配置保持原样。
func (c *Config) ConvergeSimple() {
	for i := range c.Points {
		c.Points[i].InPool = true
	}
	// 统一入口是简单模式唯一的代理地址，关掉它这一档就没意义了。
	c.Settings.AggregateEnabled = true
}

// EnsurePorts gives every access point a SOCKS5 port of its own that does
// not collide with another one or with the aggregate proxy.
func (c *Config) EnsurePorts() {
	used := map[int]bool{c.Settings.AggregatePort: true}
	next := 1081
	for i := range c.Points {
		p := &c.Points[i]
		if p.SocksPort > 0 && !used[p.SocksPort] && p.SocksPort != c.Settings.AggregatePort {
			used[p.SocksPort] = true
			continue
		}
		if p.SocksPort == 0 {
			// 0 means no per-point proxy, which is a choice, not a gap.
			continue
		}
		for used[next] || next == c.Settings.AggregatePort {
			next++
		}
		p.SocksPort = next
		used[next] = true
		next++
	}
}

// NextSocksPort returns a free per-point SOCKS5 port.
func (c *Config) NextSocksPort() int {
	c.EnsurePorts()
	used := map[int]bool{c.Settings.AggregatePort: true}
	for _, p := range c.Points {
		if p.SocksPort > 0 {
			used[p.SocksPort] = true
		}
	}
	for port := 1081; port <= 65535; port++ {
		if !used[port] {
			return port
		}
	}
	return 1081
}

// Find returns the point with id, or nil.
func (c *Config) Find(id string) *AccessPoint {
	for i := range c.Points {
		if c.Points[i].ID == id {
			return &c.Points[i]
		}
	}
	return nil
}

// Index returns the position of the point with id, or -1.
func (c *Config) Index(id string) int {
	for i := range c.Points {
		if c.Points[i].ID == id {
			return i
		}
	}
	return -1
}

// Add appends a point, giving it an ID and a free SOCKS5 port when it has
// none.
func (c *Config) Add(p AccessPoint) *AccessPoint {
	p.Normalize()
	if p.ID == "" {
		p.ID = NewID()
	}
	// A relay node has no VPN tunnel of its own, so it gets no per-point
	// SOCKS5 listener; its traffic arrives through the local aggregate entry.
	if p.SocksPort == 0 && !p.IsRelay() {
		p.SocksPort = c.NextSocksPort()
	}
	c.Points = append(c.Points, p)
	c.EnsurePorts()
	return &c.Points[len(c.Points)-1]
}

// Update replaces the point with the same ID and returns it.
func (c *Config) Update(p AccessPoint) (*AccessPoint, error) {
	i := c.Index(p.ID)
	if i < 0 {
		return nil, errors.New("接入点不存在")
	}
	p.Normalize()
	c.Points[i] = p
	c.EnsurePorts()
	return &c.Points[i], nil
}

// Remove deletes the point with id.
func (c *Config) Remove(id string) bool {
	i := c.Index(id)
	if i < 0 {
		return false
	}
	c.Points = append(c.Points[:i], c.Points[i+1:]...)
	return true
}
