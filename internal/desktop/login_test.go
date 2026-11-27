package desktop

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/ehzyil/connect-hub/internal/vpn"
)

func TestCallbackFromURL(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		{"https://vpn.example.edu.cn/passport/v1/auth/httpsOauth2?code=abc&state=x", true},
		{"https://vpn.example.edu.cn/passport/v1/auth/httpsOauth2/?code=abc", true},
		{"https://vpn.example.edu.cn/passport/v1/auth/cas?ticket=ST-1", true},
		{"https://vpn.example.edu.cn/passport/v1/auth/qywechat?code=abc&sfDomain=wechat", true},
		{"https://vpn.example.edu.cn/passport/v1/auth/qywechat?auth_code=abc&sfDomain=wechat", true},
		{"http://vpn.example.edu.cn/passport/v1/auth/httpsOauth2?code=abc", false},
		{"https://vpn.example.edu.cn/passport/v1/auth/httpsOauth2", false},
		{"https://vpn.example.edu.cn/passport/v1/auth/cas", false},
		{"https://vpn.example.edu.cn/portal", false},
	}
	for _, c := range cases {
		if _, ok := callbackFromURL(c.url); ok != c.want {
			t.Errorf("callbackFromURL(%q) = %v, want %v", c.url, ok, c.want)
		}
	}
}

func TestWeComCredentialsNeedNoPassword(t *testing.T) {
	a := testApp(t)
	var id string
	if _, err := a.store.Update(func(cfg *model.Config) error {
		p := cfg.Add(model.AccessPoint{
			Name: "扫码网关", Server: "vpn.example.edu.cn", Username: "",
			AuthMode: string(model.AuthModeWeCom), InPool: true,
		})
		id = p.ID
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	a.cfg = a.store.Config()
	creds, err := a.credentials(id)
	if err != nil {
		t.Fatalf("credentials: %v", err)
	}
	if creds.Login != "" {
		t.Errorf("login = %q", creds.Login)
	}
	if creds.ExternalLogin == nil {
		t.Error("WeCom point has no external login")
	}
}

func TestPasswordCredentials(t *testing.T) {
	a := testApp(t)
	a.openNewEditor()
	a.editor.address = "https://vpn.example.edu.cn"
	a.editor.authModeLabel = model.AuthModePassword.Label()
	a.editor.username = "alice"
	a.editor.cred = "pw-for-test"
	a.saveEditor()
	p := a.store.Config().Points[0]
	creds, err := a.credentials(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if creds.Login != "pw-for-test" {
		t.Errorf("login = %q", creds.Login)
	}
	if creds.ExternalLogin != nil {
		t.Error("password point got an external login")
	}
}

func TestExternalLoginMessage(t *testing.T) {
	// The main window is nil in this test app, so the connector's promise
	// is reported instead of trying to open a window.
	a := testApp(t)
	_, err := a.externalLogin(context.Background(), "网关", "vpn.example.edu.cn", "https://vpn.example.edu.cn/login", false)
	if err == nil {
		t.Fatal("externalLogin succeeded without a window")
	}
	if !strings.Contains(err.Error(), "主窗口") {
		t.Errorf("error = %v", err)
	}
}

func TestAutoCredentialsNeedNoPassword(t *testing.T) {
	a := testApp(t)
	var id string
	if _, err := a.store.Update(func(cfg *model.Config) error {
		p := cfg.Add(model.AccessPoint{
			Name: "自动网关", Server: "vpn.example.edu.cn",
			AuthMode: string(model.AuthModeAuto), InPool: true,
		})
		id = p.ID
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	a.cfg = a.store.Config()
	creds, err := a.credentials(id)
	if err != nil {
		t.Fatal(err)
	}
	if creds.Login != "" {
		t.Errorf("login = %q", creds.Login)
	}
	if creds.ExternalLogin == nil {
		t.Error("auto point has no external login")
	}
}

// 自动识别 is no longer offered; a new access point starts as 账号密码.
// The old "auto" value keeps working, which the test above covers.
func TestSaveDefaultEditorIsPassword(t *testing.T) {
	a := testApp(t)
	a.openNewEditor()
	if got := a.editor.authModeLabel; got != model.AuthModePassword.Label() {
		t.Fatalf("default auth mode label = %q", got)
	}
	a.editor.address = "https://vpn.example.edu.cn"
	a.editor.username = "alice"
	a.editor.cred = "pw-for-test"
	a.saveEditor()
	if a.editor.err != "" {
		t.Fatalf("save: %s", a.editor.err)
	}
	p := a.store.Config().Points[0]
	if p.AuthMode != string(model.AuthModePassword) {
		t.Errorf("auth mode = %q", p.AuthMode)
	}
}

func TestSaveSSOEditor(t *testing.T) {
	a := testApp(t)
	a.openNewEditor()
	a.editor.protocol = "aTrust"
	a.editor.address = "https://vpn.example.edu.cn"
	a.editor.authModeLabel = model.AuthModeSSO.Label()
	a.saveEditor()
	if a.editor.err != "" {
		t.Fatalf("save: %s", a.editor.err)
	}
	p := a.store.Config().Points[0]
	if p.AuthMode != string(model.AuthModeSSO) {
		t.Errorf("auth mode = %q", p.AuthMode)
	}
	if p.Username != "" {
		t.Errorf("username = %q", p.Username)
	}
}

// 单点登录 has no password to read: the browser login saved the session.
func TestSSOCredentialsNeedNoPassword(t *testing.T) {
	a := testApp(t)
	var id string
	if _, err := a.store.Update(func(cfg *model.Config) error {
		p := cfg.Add(model.AccessPoint{
			Name: "单点网关", Server: "vpn.example.edu.cn",
			AuthMode: string(model.AuthModeSSO), InPool: true,
		})
		id = p.ID
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	a.cfg = a.store.Config()
	creds, err := a.credentials(id)
	if err != nil {
		t.Fatal(err)
	}
	// 单点登录不该带账号密码：由浏览器交回授权码，客户端再自己登录。
	if creds.Login != "" || creds.TOTP != "" {
		t.Errorf("sso credentials = %+v", creds)
	}
	if browserExecutable() != "" && creds.ExternalLogin == nil {
		t.Errorf("有浏览器时应当提供取票入口，creds = %+v", creds)
	}
}

func TestParseQyWechatPoll(t *testing.T) {
	poll, err := parseQyWechatPoll([]byte(`jsonpCallback({"status":"QRCODE_SCAN_SUCC","auth_code":"abc","redirect_uri":"https://vpn.example.edu.cn/cb"})`))
	if err != nil || poll.Status != "QRCODE_SCAN_SUCC" || poll.AuthCode != "abc" {
		t.Fatalf("poll = %+v, %v", poll, err)
	}
	poll, err = parseQyWechatPoll([]byte(`{"status":"QRCODE_SCAN_NEVER"}`))
	if err != nil || poll.Status != "QRCODE_SCAN_NEVER" {
		t.Fatalf("plain poll = %+v, %v", poll, err)
	}
}

func TestQyWechatCallback(t *testing.T) {
	settings := qyWechatSettings{
		AppID: "wxapp", State: "state1", CodeType: 0,
	}
	got, err := qyWechatCallback("https://vpn.example.edu.cn/passport/v1/auth/qywechat?sfDomain=wechat", settings, "code1")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(got)
	q := u.Query()
	if q.Get("code") != "code1" || q.Get("state") != "state1" || q.Get("appid") != "wxapp" || q.Get("sfDomain") != "wechat" {
		t.Errorf("callback = %s", got)
	}

	settings.CodeType = 1
	got, _ = qyWechatCallback("https://vpn.example.edu.cn/cb", settings, "code1")
	if u, _ := url.Parse(got); u.Query().Get("auth_code") != "code1" {
		t.Errorf("service callback = %s", got)
	}
}

func TestIsQyWechatLoginURL(t *testing.T) {
	if !isQyWechatLoginURL("https://open.work.weixin.qq.com/wwopen/sso/qrConnect?appid=x") {
		t.Error("qrConnect not recognized")
	}
	if isQyWechatLoginURL("https://open.work.weixin.qq.com/other") {
		t.Error("other page recognized")
	}
	if isQyWechatLoginURL("https://vpn.example.edu.cn/portal") {
		t.Error("vpn page recognized")
	}
}

func TestWWCallback(t *testing.T) {
	s := wwLoginSettings{
		RedirectURI: "https://vpn.example.edu.cn/passport/v1/auth/qywechat?sfDomain=wechat",
		State:       "st1", AppID: "wx1",
	}
	got := wwCallback(s, "code1")
	u, _ := url.Parse(got)
	q := u.Query()
	if q.Get("code") != "code1" || q.Get("state") != "st1" || q.Get("sfDomain") != "wechat" {
		t.Errorf("callback = %s", got)
	}
	if !callbackFromURLAllowed(got, "vpn.example.edu.cn") {
		t.Errorf("callback not accepted: %s", got)
	}
}

func TestIsWWLoginURL(t *testing.T) {
	if !isWWLoginURL("https://login.work.weixin.qq.com/wwlogin/sso/login?x=1") {
		t.Error("wwlogin not recognized")
	}
	if isWWLoginURL("https://open.work.weixin.qq.com/wwopen/sso/qrConnect") {
		t.Error("qr page misclassified")
	}
}

func TestLandedOnPortal(t *testing.T) {
	const server = "zeroportal.example.net"
	cases := []struct {
		url  string
		want bool
	}{
		{"https://zeroportal.example.net:8888/portal/", true},
		{"https://zeroportal.example.net/portal", true},
		{"https://zeroportal.example.net/portal/shortcut.html", true},
		{"https://zeroportal.example.net/passport/v1/auth/cas?ticket=ST-1", false},
		{"https://zeroportal.example.net/passport/v1/public/casLogin", false},
		{"https://idaas.example.cn/login", false},
		{"http://zeroportal.example.net/portal/", false},
		{"", false},
	}
	for _, c := range cases {
		if got := landedOnPortal(c.url, server); got != c.want {
			t.Errorf("landedOnPortal(%q) = %v, want %v", c.url, got, c.want)
		}
	}
}

func TestCallbackFromURLTakesTicketAndCode(t *testing.T) {
	cas := "https://a.example.net/passport/v1/auth/cas?sfDomain=cas1&ticket=ST-42"
	raw, ok := callbackFromURL(cas)
	if !ok || raw != cas {
		t.Fatalf("cas callback: %q %v", raw, ok)
	}
	if _, ok := callbackFromURL("https://a.example.net/passport/v1/auth/cas?sfDomain=cas1"); ok {
		t.Fatal("没有 ticket 不应算回调")
	}
	if _, ok := callbackFromURL("https://a.example.net/portal/"); ok {
		t.Fatal("门户页不应算回调")
	}
}

func TestParsePasteProbe(t *testing.T) {
	href, text := parsePasteProbe(`["https://a.net/x#devtools","https://a.net/passport/v1/auth/cas?ticket=1"]`)
	if !strings.Contains(href, "#devtools") || !strings.HasPrefix(text, "https://") {
		t.Fatalf("href=%q text=%q", href, text)
	}
	if h, x := parsePasteProbe("nope"); h != "" || x != "" {
		t.Fatal("坏输入应返回空")
	}
}

func TestHostSet(t *testing.T) {
	h := &hostSet{hosts: map[string]bool{}}
	h.add("ZeroPortal.Example.Net")
	if !h.has("zeroportal.example.net") || !h.has("ZEROPORTAL.EXAMPLE.NET") {
		t.Fatal("主机名应大小写无关")
	}
	if h.has("idaas.example.cn") {
		t.Fatal("未访问的主机不应放行")
	}
	h.add("")
	if len(h.hosts) != 1 {
		t.Fatalf("空主机不应记录：%v", h.hosts)
	}
}

// 短信 / 动态口令 / RADIUS 验证码必须走应用内弹窗。GUI 子系统进程没有
// 标准输入，少了这个回调，zju-connect 的 auth 包会去读 stdin 并永远卡住
// （Windows 上表现为 read /dev/stdin: The handle is invalid）。
func TestPasswordCredentialsAskCodesInApp(t *testing.T) {
	a := testApp(t)
	a.openNewEditor()
	a.editor.address = "https://vpn.example.edu.cn"
	a.editor.authModeLabel = model.AuthModePassword.Label()
	a.editor.username = "alice"
	a.editor.cred = "pw-for-test"
	a.saveEditor()
	p := a.store.Config().Points[0]
	creds, err := a.credentials(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if creds.PromptCode == nil {
		t.Fatal("凭据没有 PromptCode：验证码会去读不存在的标准输入")
	}
}

func TestCodeChallengeKinds(t *testing.T) {
	cases := []struct {
		req  vpn.CodeRequest
		want string
	}{
		{vpn.CodeRequest{Kind: vpn.CodeSMS, Tip: "已发送"}, "sms"},
		{vpn.CodeRequest{Kind: vpn.CodeCustomSMS}, "sms"},
		{vpn.CodeRequest{Kind: vpn.CodeTOTP}, "totp"},
		{vpn.CodeRequest{Kind: vpn.CodeRADIUS}, "radius"},
	}
	for _, c := range cases {
		got := codeChallenge(c.req)
		if got.Kind != c.want {
			t.Errorf("codeChallenge(%v).Kind = %q，想要 %q", c.req.Kind, got.Kind, c.want)
		}
		if got.Tip != c.req.Tip {
			t.Errorf("codeChallenge(%v).Tip = %q，想要 %q", c.req.Kind, got.Tip, c.req.Tip)
		}
	}
}

// 没人理验证码弹窗时必须按护栏超时收场：不能拖到连接的 5 分钟截止，
// 也不能把弹窗留在界面上。
func TestCodePromptGivesUpWhenUnanswered(t *testing.T) {
	a := testApp(t)
	a.openNewEditor()
	a.editor.address = "https://vpn.example.edu.cn"
	a.editor.authModeLabel = model.AuthModePassword.Label()
	a.editor.username = "alice"
	a.editor.cred = "pw-for-test"
	a.saveEditor()
	p := a.store.Config().Points[0]
	creds, err := a.credentials(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	old := loginCodeTimeout
	loginCodeTimeout = 40 * time.Millisecond
	defer func() { loginCodeTimeout = old }()

	start := time.Now()
	if _, err := creds.PromptCode(context.Background(), vpn.CodeRequest{Kind: vpn.CodeSMS}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("无人应答时应超时，得到 %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("护栏没有生效，等了 %v", elapsed)
	}
	a.authMu.Lock()
	left := a.authRequest
	a.authMu.Unlock()
	if left != nil {
		t.Fatal("超时后认证弹窗仍挂在界面上")
	}
}
