package contract

import (
	"context"
	"net"

	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/ehzyil/connect-hub/internal/workeripc"
)

// Challenge is an interactive login challenge from a gateway.
type Challenge struct {
	ID    string
	Kind  string
	Image []byte
	// Tip is what the server said when it sent the code, e.g. "验证码
	// 已发送到您的手机：138****0000，请查收！". Empty when it said nothing.
	Tip string
}

// Credentials are what the secret store holds for an access point.
type Credentials struct {
	Challenge func(context.Context, Challenge) (string, error)
	Login     string
	TOTP      string
	// ExternalLogin shows loginURL to the user, as a QR code or a browser
	// page, and returns the https callback URL the identity provider
	// redirects to. It is what the WeCom (external OAuth2/CAS) mode uses;
	// the password mode leaves it nil.
	ExternalLogin func(ctx context.Context, loginURL string) (string, error)
	// PromptCode 询问登录卡住的验证码，短信与令牌都走这里；为空时没有
	// 交互窗口，只能在终端输入。
	PromptCode func(ctx context.Context, req CodeRequest) (string, error)
}

type CodeRequest struct {
	Kind CodeKind
	Tip  string
}

type CodeKind int

const (
	CodeSMS CodeKind = iota
	CodeCustomSMS
	CodeTOTP
	CodeRADIUS
)

// Session is one logged-in access point.
type Session interface {
	// Dial opens a connection through the VPN tunnel.
	Dial(ctx context.Context, network, addr string) (net.Conn, error)
	// Info describes the session for the UI.
	Info() SessionInfo
	// Close logs out and releases the tunnel.
	Close() error
}

// StrictSession never falls back to the original network. Routing must require
// this capability for a destination claimed by a gateway.
type StrictSession interface {
	DialVPN(ctx context.Context, network, addr string) (net.Conn, error)
}

// StrictUDPSession belongs to one live worker generation, never an OS route.
type StrictUDPSession interface {
	StrictSession
	SupportsStrictUDP() bool
	Done() <-chan struct{}
}

// SessionInfo is what a Session reports about itself.
type SessionInfo struct {
	ClientIP     string
	DNSServer    string
	NodeGroups   []string
	BestNodes    map[string]string
	HealthTarget string
	Apps         []App
	Resources    *workeripc.ResourceSnapshot
}

// Connector logs in to one access point. It blocks until the login either
// succeeds or fails, and must honor ctx.
type Connector func(ctx context.Context, point model.AccessPoint, creds Credentials) (Session, error)

// CredentialFunc reads the stored creds of an access point.
type CredentialFunc func(id string) (Credentials, error)
