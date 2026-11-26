package contract

import (
	"testing"
)

func TestExpandHostRange(t *testing.T) {
	got := expandHostRange("10.20.162.68-10.20.162.69")
	if len(got) != 2 || got[0] != "10.20.162.68" || got[1] != "10.20.162.69" {
		t.Errorf("range = %v", got)
	}
	if ips := (App{Addresses: []AppAddress{{Host: "10.0.0.1-10.0.0.3", Port: "1-65535"}}}).ProbeHosts(); len(ips) != 3 {
		t.Errorf("probe hosts = %v", ips)
	}
	cidr := expandHostRange("192.168.38.0/30")
	if len(cidr) != 4 {
		t.Errorf("cidr = %v", cidr)
	}
	if single := expandHostRange("10.0.0.9"); len(single) != 1 || single[0] != "10.0.0.9" {
		t.Errorf("single = %v", single)
	}
}
