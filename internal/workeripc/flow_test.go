package workeripc

import "testing"

func TestFlowReportValidation(t *testing.T) {
	base := FlowResult{Target: "db.corp.test:5432", DialAddress: "10.0.0.2:5432", Route: "vpn", Rule: "domain_resource", Domain: "*.corp.test", Protocol: "tcp", PortMin: 5432, PortMax: 5432}
	if !ValidFlowResult(base) {
		t.Fatal("valid result rejected")
	}
	for _, mutate := range []func(*FlowResult){
		func(r *FlowResult) { r.Target = "user:password@host:443" },
		func(r *FlowResult) { r.Target = "host\nforged:443" },
		func(r *FlowResult) { r.Target = "host:65536" },
		func(r *FlowResult) { r.Failure = "raw gateway password" },
		func(r *FlowResult) { r.Route = "blocked" },
		func(r *FlowResult) { r.Protocol = "token" },
		func(r *FlowResult) { r.Rule = "ip_resource"; r.IPMin = "not-an-ip" },
	} {
		r := base
		mutate(&r)
		if ValidFlowResult(r) {
			t.Fatalf("invalid result accepted: %+v", r)
		}
	}
}
