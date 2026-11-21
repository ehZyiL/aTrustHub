package main

import (
	"strings"
	"testing"

	"github.com/ehZyiL/connect-hub/internal/vpn"
)

func TestHealthLabelsDoNotClaimUnverifiedBusinessSuccess(t *testing.T) {
	for _, kind := range []string{"DNS", "TCP"} {
		if text := healthProbeText(kind, vpn.ProbeResult{}); !strings.Contains(text, "未验证") {
			t.Fatal("missing evidence presented as success", text)
		}
	}
	failed := healthProbeText("TCP", vpn.ProbeResult{State: "failed", Target: "10.1.2.3:3306", Error: "connection refused"})
	if !strings.Contains(failed, "探测失败") || !strings.Contains(failed, "10.1.2.3:3306") || !strings.Contains(failed, "connection refused") {
		t.Fatal("failed port evidence hidden", failed)
	}
	connected := healthProbeText("TCP", vpn.ProbeResult{State: "ok", Target: "10.1.2.3:3306"})
	if !strings.Contains(connected, "已通过 VPN 建立") || !strings.Contains(connected, "业务操作未验证") {
		t.Fatal("TCP handshake claimed application health", connected)
	}
	dns := healthProbeText("DNS", vpn.ProbeResult{State: "ok"})
	if !strings.Contains(dns, "有应答") || strings.Contains(dns, "TCP") {
		t.Fatal("DNS response claimed business connectivity", dns)
	}
}
