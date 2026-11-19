package main

import (
	"github.com/miekg/dns"
	"testing"
)

func TestDNSProbeOnlyAcceptsDomainQuestions(t *testing.T) {
	for _, name := range []string{"https://corp.example/", "127.0.0.1", "corp.example:443", "*.corp.example", "", "bad name"} {
		if _, err := dnsProbeQuestion(name, "A"); err == nil {
			t.Fatalf("invalid diagnostic input accepted: %q", name)
		}
	}
	packet, err := dnsProbeQuestion(" db.corp.example. ", "AAAA")
	if err != nil {
		t.Fatal(err)
	}
	m := new(dns.Msg)
	if m.Unpack(packet) != nil || len(m.Question) != 1 || m.Question[0].Name != "db.corp.example." || m.Question[0].Qtype != dns.TypeAAAA {
		t.Fatal("invalid question")
	}
}
