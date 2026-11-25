package relay

import "testing"

// A VPN session may list an address where a domain is expected. Such an entry
// cannot be published, but it must not make the whole share unusable either:
// it is dropped and everything valid survives.
func TestDropUnusableDomainsKeepsTheValidOnes(t *testing.T) {
	s := &ResourceSnapshot{
		DomainRules: []DomainRule{
			{Domain: "git.corp.test", PortMin: 443, PortMax: 443, Protocol: "tcp"},
			{Domain: "1.2.3.4", PortMin: 443, PortMax: 443, Protocol: "tcp"},
			{Domain: "10.0.0.0/8", PortMin: 443, PortMax: 443, Protocol: "tcp"},
			{Domain: "*.corp.test", PortMin: 443, PortMax: 443, Protocol: "tcp"},
			{Domain: "", PortMin: 443, PortMax: 443, Protocol: "tcp"},
			{Domain: "bad name", PortMin: 443, PortMax: 443, Protocol: "tcp"},
		},
		InternalDomains: []string{"corp.test", "192.168.31.1", "also.corp.test"},
		// Static DNS names go through the same validator, so an address here
		// failed the whole snapshot just like a domain rule did.
		StaticDNS: []DNSRecord{
			{Name: "vpn.corp.test", Addresses: []string{"10.0.0.2"}},
			{Name: "10.0.0.1", Addresses: []string{"10.0.0.3"}},
		},
	}
	// The boundary stays strict for whatever still reaches it.
	if err := s.Validate(); err == nil {
		t.Fatal("未清理的快照不应通过校验")
	}
	dropped := s.DropUnusableDomains()
	if dropped != 6 {
		t.Fatalf("丢弃了 %d 条，want 6", dropped)
	}
	if err := s.Validate(); err != nil {
		t.Fatalf("清理后仍不合法：%v", err)
	}
	var names []string
	for _, r := range s.DomainRules {
		names = append(names, r.Domain)
	}
	if len(names) != 2 || names[0] != "git.corp.test" || names[1] != "*.corp.test" {
		t.Fatalf("保留的域名不对：%v", names)
	}
	if len(s.InternalDomains) != 2 || s.InternalDomains[0] != "corp.test" {
		t.Fatalf("保留的内部域名不对：%v", s.InternalDomains)
	}
	if len(s.StaticDNS) != 1 || s.StaticDNS[0].Name != "vpn.corp.test" {
		t.Fatalf("保留的静态 DNS 不对：%+v", s.StaticDNS)
	}
	// Idempotent: a second pass finds nothing to drop.
	if again := s.DropUnusableDomains(); again != 0 {
		t.Fatalf("第二次又丢弃了 %d 条", again)
	}
}

func TestDomainUsable(t *testing.T) {
	for _, name := range []string{"corp.test", "*.corp.test", "a-b.c0rp.test"} {
		if !DomainUsable(name) {
			t.Fatalf("%q 应当可用", name)
		}
	}
	for _, name := range []string{"1.2.3.4", "10.0.0.0/8", "", "bad name", "a:b", "host:443"} {
		if DomainUsable(name) {
			t.Fatalf("%q 不应当可用", name)
		}
	}
}
