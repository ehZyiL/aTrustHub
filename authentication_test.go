package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/ehzyil/connect-hub/internal/vpn"
)

func TestEasyConnectEditorAndAuthModal(t *testing.T) {
	a := testApp(t)
	a.openNewEditor()
	if a.editor.protocol != "EasyConnect" {
		t.Fatal("new entries must default to EasyConnect")
	}
	a.editor.name, a.editor.address, a.editor.username, a.editor.cred = "test", "https://gateway.invalid", "test", "test-password"
	a.editor.remoteDNS = "10.0.0.53"
	a.editor.internalDomains = "corp.test, internal.test"
	a.saveEditor()
	if a.editor.err != "" {
		t.Fatal(a.editor.err)
	}
	p := a.store.Config().Points[0]
	if p.Protocol != model.ProtocolEasyConnect || len(p.InternalDomains) != 2 {
		t.Fatal("EasyConnect settings not saved")
	}
	a.loginSem = make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan string, 1)
	go func() {
		value, _ := a.requestAuthentication(ctx, "test", vpn.Challenge{Kind: "totp", ID: "one"})
		result <- value
	}()
	deadline := time.Now().Add(time.Second)
	for {
		a.authMu.Lock()
		ready := a.authRequest != nil
		a.authMu.Unlock()
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no challenge")
		}
		time.Sleep(time.Millisecond)
	}
	tt := ui.NewTester(a.view, 1120, 800)
	if !strings.Contains(strings.Join(tt.Texts(), "|"), "动态口令") {
		t.Fatal("missing auth dialog")
	}
	a.authDraft.value = "test-code"
	tt.Frame()
	if err := tt.Click("提交验证码"); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-result:
		if got != "test-code" {
			t.Fatal(got)
		}
	case <-time.After(time.Second):
		t.Fatal("answer not delivered")
	}
	tt.Frame()
	if a.authDraft.value != "" || a.authDraft.request != nil {
		t.Fatal("challenge retained after completion")
	}
}
