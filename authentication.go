package main

import (
	"bytes"
	"context"
	"errors"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"strings"

	"github.com/egoist/mygo/ui"
	"github.com/ehzyil/connect-hub/internal/vpn"
)

type authenticationAnswer struct {
	value string
	err   error
}
type authenticationRequest struct {
	name      string
	challenge vpn.Challenge
	answer    chan authenticationAnswer
}
type authenticationDraft struct {
	request *authenticationRequest
	open    bool
	value   string
	image   ui.ImageSource
	err     string
}

func (a *app) requestAuthentication(ctx context.Context, name string, ch vpn.Challenge) (string, error) {
	select {
	case a.loginSem <- struct{}{}:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	defer func() { <-a.loginSem }()
	if ch.Kind == "captcha" {
		cfg, _, err := image.DecodeConfig(bytes.NewReader(ch.Image))
		if err != nil || len(ch.Image) > 512<<10 || cfg.Width < 1 || cfg.Height < 1 || cfg.Width > 2048 || cfg.Height > 2048 {
			return "", errors.New("网关返回的验证码图片无法显示")
		}
	}
	r := &authenticationRequest{name: name, challenge: ch, answer: make(chan authenticationAnswer, 1)}
	a.authMu.Lock()
	a.authRequest = r
	a.authMu.Unlock()
	a.invalidate()
	defer func() {
		a.authMu.Lock()
		if a.authRequest == r {
			a.authRequest = nil
		}
		a.authMu.Unlock()
		a.invalidate()
	}()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case reply := <-r.answer:
		return reply.value, reply.err
	}
}

func (a *app) authenticationView(c *ui.Context) {
	a.authMu.Lock()
	r := a.authRequest
	a.authMu.Unlock()
	if r == nil {
		a.authDraft = authenticationDraft{}
		return
	}
	if a.authDraft.request != r {
		a.authDraft = authenticationDraft{request: r, open: true}
		if len(r.challenge.Image) != 0 {
			a.authDraft.image, _ = ui.DecodeBitmap(r.challenge.Image)
		}
	}
	d := &a.authDraft
	answer := func(value string, err error) {
		select {
		case r.answer <- authenticationAnswer{value, err}:
		default:
		}
		d.value, d.image, d.open = "", nil, false
	}
	if !d.open {
		answer("", context.Canceled)
		return
	}
	ui.Modal(c, &d.open, func() {
		ui.Column(c).Width(dialogNarrow).Gap(10).Children(func() {
			dialogHeader(c, "完成认证", r.name+" · 验证码仅用于当前登录，不会保存")
			if tip := strings.TrimSpace(r.challenge.Tip); tip != "" {
				ui.Text(c, tip).FontSize(11).TextColor(c.Theme().TextMuted)
			}
			label := "动态口令"
			switch r.challenge.Kind {
			case "sms":
				label = "短信验证码"
			case "captcha":
				label = "图形验证码"
			case "radius":
				label = "认证验证码"
			case "device":
				label = "设备验证码"
			}
			if d.image != nil {
				ui.Image(c, d.image).Size(240, 100)
			}
			ui.Field(c, label, func() { ui.TextInput(c, &d.value).Placeholder("请输入当前验证码") })
			ui.Text(c, "关闭弹窗将取消本次连接。").FontSize(11).TextColor(c.Theme().TextMuted)
			dialogFooter(c, func() {
				ui.Row(c).Grow(1)
				if ui.Button(c, "取消认证").FontSize(11).Clicked() {
					answer("", context.Canceled)
				}
				if ui.PrimaryButton(c, "提交验证码").FontSize(11).
					Disabled(strings.TrimSpace(d.value) == "").Clicked() {
					answer(strings.TrimSpace(d.value), nil)
				}
			})
		})
	})
	if !d.open {
		answer("", context.Canceled)
	}
}
