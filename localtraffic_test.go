package main

import (
	"strings"
	"testing"

	"github.com/ehzyil/connect-hub/internal/localapps"
	"github.com/ehzyil/connect-hub/internal/vpn"
	"github.com/ehzyil/connect-hub/internal/workeripc"
)

func TestLocalAccessLogDoesNotInferVPNOrExposeURLCredentials(t *testing.T) {
	source, line := localAccessLine(localapps.AccessEvent{Name: "IDE\nforged\u202e", Target: "https://user:secret@site.test/path?token=sensitive", Result: workeripc.FlowResult{Route: "unknown"}})
	if source != vpn.AccessOK || !strings.Contains(line, "路径未报告") || strings.ContainsAny(line, "\n\r\u202e") || strings.Contains(line, "secret") || strings.Contains(line, "sensitive") {
		t.Fatal(line)
	}
	source, line = localAccessLine(localapps.AccessEvent{Name: "database", Target: "10.0.0.1:5432", Result: workeripc.FlowResult{Route: "vpn", Rule: "ip_resource", IPMin: "10.0.0.1", IPMax: "10.0.0.1", Protocol: "tcp", PortMin: 5432, PortMax: 5432, Failure: "timeout"}})
	if source != vpn.AccessFail || !strings.Contains(line, "尝试 VPN") || !strings.Contains(line, "连接超时") || strings.Contains(line, "TCP 已建立") {
		t.Fatal(line)
	}
}
