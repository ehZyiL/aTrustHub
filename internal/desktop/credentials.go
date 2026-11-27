package desktop

import (
	"context"
	"errors"
	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/ehzyil/connect-hub/internal/store"
	"github.com/ehzyil/connect-hub/internal/vpn"
	"strings"
	"time"
)

// credentials reads what the manager needs for one login.
//
// The flow follows the configured auth mode, so the same "登录" button
// works everywhere: the password mode signs in by itself, WeCom opens the
// QR popup, and third-party SSO resumes the session the browser login
// saved.
func (a *app) credentials(id string) (vpn.Credentials, error) {
	cfg := a.configForBackground()
	point := cfg.Find(id)
	mode := model.AuthModePassword
	if point != nil && point.AuthMode != "" {
		mode = model.AuthMode(point.AuthMode)
	}
	var external func(context.Context, string) (string, error)
	if point != nil && (mode == model.AuthModeAuto || mode == model.AuthModeWeCom) {
		name, server := point.Name, point.Server
		// WeCom always uses the app's own popup now. Only a legacy "auto"
		// point keeps the old "hand over to the system browser" switch.
		inBrowser := mode == model.AuthModeAuto && point.LoginInBrowser
		external = func(ctx context.Context, loginURL string) (string, error) {
			cb, err := a.externalLogin(ctx, name, server, loginURL, inBrowser)
			if errors.Is(err, errWeComLocalUnavailable) && point != nil && browserExecutable() != "" {
				// 客户端只把本地桥开放给浏览器，本程序直接连会被重置；这时
				// 交给真实浏览器，页面自己会去敲本地桥并弹确认框。
				a.tunLogf("[%s] 本地企业微信认证不可用，改用系统浏览器完成", name)
				return a.cdpLoginCallback(ctx, point, loginURL)
			}
			return cb, err
		}
	}
	switch mode {
	case model.AuthModeWeCom:
		if external == nil {
			return vpn.Credentials{}, vpn.ErrNoCredentials
		}
		return vpn.Credentials{ExternalLogin: external}, nil
	case model.AuthModeSSO:
		// 这里没有账号密码：由真正的浏览器走完单点登录并交回授权码，
		// 登录本身仍由客户端完成，隧道才用得上它自己的设备号与签名。
		if browserExecutable() != "" {
			return vpn.Credentials{ExternalLogin: func(cbCtx context.Context, loginURL string) (string, error) {
				return a.cdpLoginCallback(cbCtx, point, loginURL)
			}}, nil
		}
		// 没有 Chromium 时退回应用内置窗口，走同一条单点登录。
		if external != nil {
			return vpn.Credentials{ExternalLogin: external}, nil
		}
		return vpn.Credentials{}, nil
	}

	cred, err := a.store.Password(id)
	if err != nil {
		if strings.Contains(err.Error(), "User canceled") || strings.Contains(err.Error(), "-128") {
			return vpn.Credentials{}, errors.New("读取密码失败：钥匙串访问被取消。请重新登录，并在系统弹窗点「允许」，或编辑接入点重新输入密码")
		}
		if errors.Is(err, store.ErrSecretNotFound) {
			if mode == model.AuthModeAuto {
				// Auto can still use an external login.
				return vpn.Credentials{ExternalLogin: external}, nil
			}
			return vpn.Credentials{}, vpn.ErrNoCredentials
		}
		return vpn.Credentials{}, err
	}
	// EasyConnect requests fresh codes through its challenge handler. A missing
	// or locked keyring must not block a password kept in the session fallback.
	var totp string
	if point == nil || point.Protocol != model.ProtocolEasyConnect {
		totp, err = a.store.TOTP(id)
		if err != nil && !errors.Is(err, store.ErrSecretNotFound) {
			return vpn.Credentials{}, err
		}
	}
	creds := vpn.Credentials{Login: cred, TOTP: totp, ExternalLogin: external}
	// 短信 / 动态口令 / RADIUS 验证码由 zju-connect 的 auth 包主动询问。
	// 不接这里，它就去读标准输入；GUI 子系统进程（Windows 的
	// -H windowsgui）根本没有 stdin，登录会永远卡在 read /dev/stdin。
	codeName := id
	if point != nil && point.Name != "" {
		codeName = point.Name
	}
	creds.PromptCode = func(ctx context.Context, req vpn.CodeRequest) (string, error) {
		// 没人理这个弹窗时不要拖到连接的 5 分钟超时：那会把登录信号量
		// 也一直占着，后面的重试只能干等。
		ctx, cancel := context.WithTimeout(ctx, loginCodeTimeout)
		defer cancel()
		return a.requestAuthentication(ctx, codeName, codeChallenge(req))
	}
	if point != nil && point.Protocol == model.ProtocolEasyConnect {
		name := point.Name
		creds.Challenge = func(ctx context.Context, ch vpn.Challenge) (string, error) {
			return a.requestAuthentication(ctx, name, ch)
		}
	}
	return creds, nil
}

// loginCodeTimeout bounds how long a code dialog may stay unanswered before
// the login gives up. It is shorter than the 5-minute connect deadline on
// purpose: one abandoned dialog must not hold the login slot for the whole
// connection attempt. A variable so the guard is testable.
var loginCodeTimeout = 3 * time.Minute

// codeChallenge turns one login code request into the shape the app's
// authentication dialog already draws: the same modal asks for EasyConnect
// captchas and for aTrust SMS/TOTP/RADIUS codes.
func codeChallenge(req vpn.CodeRequest) vpn.Challenge {
	kind := "totp"
	switch req.Kind {
	case vpn.CodeSMS, vpn.CodeCustomSMS:
		kind = "sms"
	case vpn.CodeRADIUS:
		kind = "radius"
	}
	return vpn.Challenge{Kind: kind, Tip: req.Tip}
}

func (a *app) hasPassword(id string) bool {
	_, err := a.store.Password(id)
	return err == nil
}

func (a *app) hasTOTP(id string) bool {
	_, err := a.store.TOTP(id)
	return err == nil
}
