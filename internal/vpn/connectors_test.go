package vpn

import (
	"context"
	"errors"
	"testing"

	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/mythologyli/zju-connect/client/atrust/auth"
)

func TestOptionalProtocolNeverFallsBackToAnotherLogin(t *testing.T) {
	calls := 0
	base := func(context.Context, model.AccessPoint, Credentials) (Session, error) { calls++; return nil, nil }
	connect := Dispatch(Registration{Protocol: model.ProtocolATrust, Connect: base})
	for _, protocol := range []string{model.ProtocolLANRelay, "unknown"} {
		_, err := connect(context.Background(), model.AccessPoint{Protocol: protocol}, Credentials{Login: "share-secret"})
		var unavailable *UnavailableProtocolError
		if !errors.As(err, &unavailable) {
			t.Fatalf("missing %s = %v", protocol, err)
		}
	}
	if calls != 0 {
		t.Fatal("optional credential reached base login")
	}
	_, _ = connect(context.Background(), model.AccessPoint{}, Credentials{})
	if calls != 1 {
		t.Fatal("legacy empty protocol no longer selects aTrust")
	}
}

func TestExplicitRegistrationAndCancellation(t *testing.T) {
	calls := 0
	optional := func(context.Context, model.AccessPoint, Credentials) (Session, error) { calls++; return nil, nil }
	connect := NewProtocolConnector(ZJUOptions{}, Registration{Protocol: model.ProtocolLANRelay, Connect: optional})
	_, err := connect(context.Background(), model.AccessPoint{Protocol: model.ProtocolLANRelay}, Credentials{})
	if err != nil || calls != 1 {
		t.Fatalf("registration: %v (%d calls)", err, calls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = connect(ctx, model.AccessPoint{Protocol: model.ProtocolLANRelay}, Credentials{})
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatal("cancelled call reached connector")
	}
	connect = Dispatch(Registration{Protocol: "duplicate", Connect: optional}, Registration{Protocol: "duplicate", Connect: optional})
	if _, err = connect(context.Background(), model.AccessPoint{Protocol: "duplicate"}, Credentials{}); err == nil || calls != 1 {
		t.Fatal("duplicate registry ran a connector")
	}
}

func TestAuthPromptAdapterKeepsKinds(t *testing.T) {
	for in, want := range map[auth.CodeKind]CodeKind{auth.CodeSMS: CodeSMS, auth.CodeCustomSMS: CodeCustomSMS, auth.CodeTOTP: CodeTOTP, auth.CodeRADIUS: CodeRADIUS} {
		got, err := codeKindFromAuth(in)
		if err != nil || got != want {
			t.Fatalf("%d -> %d: %v", in, got, err)
		}
	}
	if _, err := codeKindFromAuth(99); err == nil {
		t.Fatal("unknown prompt silently changed kind")
	}
}
