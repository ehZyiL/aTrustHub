package adapter

import (
	"errors"
	"strings"
	"testing"

	"github.com/ehzyil/connect-hub/internal/relay"
)

func reconnectable(err error) bool {
	var re *relay.Error
	return !errors.As(err, &re) || !re.Code.Terminal()
}

// R6: the friendly wording replaced the typed error with errors.New, so a
// terminal share failure looked reconnectable again.
func TestFriendlyRelayErrorKeepsTerminalClassification(t *testing.T) {
	terminal := []relay.Code{relay.CodeShareClosed, relay.CodeInvalidCredentials, relay.CodeProtocolUnsupported}
	for _, code := range terminal {
		friendly := friendlyRelayError(relay.NewError(code, "raw"))
		if reconnectable(friendly) {
			t.Fatalf("%s became reconnectable after presentation: %v", code, friendly)
		}
		var re *relay.Error
		if !errors.As(friendly, &re) || re.Code != code {
			t.Fatalf("%s lost its type through presentation: %v", code, friendly)
		}
		if strings.Contains(friendly.Error(), "raw") {
			t.Fatalf("%s still shows the protocol text: %v", code, friendly)
		}
	}
	// Transient failures must keep their bounded reconnect budget.
	if !reconnectable(friendlyRelayError(relay.NewError(relay.CodeVPNUnavailable, "broken pipe"))) {
		t.Fatal("a transient share error stopped being reconnectable")
	}
	// A plain error is not a share error and keeps the old behaviour.
	if !reconnectable(errors.New("dial failed")) {
		t.Fatal("plain errors must stay reconnectable")
	}
}

func TestPairedDeviceFailureKeepsClassificationAndPairingGuidance(t *testing.T) {
	err := friendlyRelayErrorForVersion(relay.NewError(relay.CodeInvalidCredentials, "raw"), 2)
	if reconnectable(err) || !strings.Contains(err.Error(), "重新配对") || strings.Contains(err.Error(), "新口令") {
		t.Fatal("v2 failure lost terminal classification or used v1 recovery", err)
	}
}
