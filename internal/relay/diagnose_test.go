package relay

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestDiagnoseSuccess(t *testing.T) {
	fx := startShareFixture(t, "share-token-123456")
	code := fx.code
	// The fixture identity covers 127.0.0.1, and the client verifies that.
	report := Diagnose(context.Background(), code, DiagnoseOptions{Target: "10.1.2.3:443"})
	if report.Failed() {
		t.Fatalf("diagnose reported a failure:\n%s", strings.Join(FormatReport(report), "\n"))
	}
	lines := strings.Join(FormatReport(report), "\n")
	for _, want := range []string{"TCP 连接已建立", "证书指纹与口令一致", "分享登录成功", "业务连接已建立"} {
		if !strings.Contains(lines, want) {
			t.Fatalf("report lacks %q:\n%s", want, lines)
		}
	}
}

func TestDiagnoseWrongFingerprint(t *testing.T) {
	fx := startShareFixture(t, "share-token-123456")
	code := fx.code
	code.Fingerprint = strings.Repeat("0", 64)
	report := Diagnose(context.Background(), code, DiagnoseOptions{})
	if !report.Failed() {
		t.Fatal("wrong pin must fail the identity step")
	}
	if report.Steps[len(report.Steps)-1].Stage != StageTLS {
		t.Fatalf("diagnose continued past a pin mismatch: %+v", report.Steps)
	}
}

func TestDiagnoseRefusedIsNotBlamedOnFirewall(t *testing.T) {
	// Bind then close a port so the connection is refused rather than hanging.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	_ = ln.Close()
	code := ShareCode{Version: 1, Host: "127.0.0.1", Port: addr.Port,
		ShareID: "x", Token: "y", Fingerprint: strings.Repeat("a", 64)}
	report := Diagnose(context.Background(), code, DiagnoseOptions{Timeout: 2 * time.Second})
	if !report.Failed() {
		t.Fatal("a closed port must fail")
	}
	lines := strings.Join(FormatReport(report), "\n")
	if strings.Contains(lines, "防火墙未放行") {
		t.Fatalf("a refusal must not be reported as a firewall verdict:\n%s", lines)
	}
	if !strings.Contains(lines, "拒绝") && !strings.Contains(lines, "未唯一确定") {
		t.Fatalf("unexpected wording:\n%s", lines)
	}
}

func TestDiagnoseDeniedTargetIsDefinite(t *testing.T) {
	fx := startShareFixture(t, "share-token-123456")
	report := Diagnose(context.Background(), fx.code, DiagnoseOptions{Target: "8.8.8.8:443"})
	if !report.Failed() {
		t.Fatal("an unauthorized target must fail the business step")
	}
	last := report.Steps[len(report.Steps)-1]
	if last.Stage != StageBusiness || last.Uncertain {
		t.Fatalf("denied target should be a definite business fact: %+v", last)
	}
}
