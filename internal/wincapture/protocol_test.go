package wincapture

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/qy/easyconnect/internal/netpolicy"
)

func TestHelperScopeValidation(t *testing.T) {
	valid := Config{Gateway: "vpn.example.test", Networks: []netpolicy.Range{{Min: "10.44.0.1", Max: "10.44.0.254"}}, Domains: []string{"internal.example.test"}, DNSAddress: "127.0.0.1:21001"}
	if err := valid.validate(); err != nil {
		t.Fatal(err)
	}
	for _, domain := range []string{".", "com", "internal.example.test';exit", "internal..test", "*.example.test", "-internal.example.test"} {
		bad := valid
		bad.Domains = []string{domain}
		if err := bad.validate(); err == nil {
			t.Fatalf("accepted unsafe DNS namespace %q", domain)
		}
	}
	for _, address := range []string{"0.0.0.0:21001", "192.0.2.1:21001", "127.0.0.1:53", "[::1]:21001"} {
		bad := valid
		bad.DNSAddress = address
		if err := bad.validate(); err == nil {
			t.Fatalf("accepted non-session DNS %q", address)
		}
	}
	bad := valid
	bad.Gateway = ""
	if err := bad.validate(); err == nil {
		t.Fatal("accepted missing gateway protection")
	}
	upstream := Upstream{Address: "127.0.0.1:21002", Username: "capture", Password: strings.Repeat("x", 64)}
	if err := upstream.validate(); err != nil {
		t.Fatal(err)
	}
	upstream.Password = ""
	if err := upstream.validate(); err == nil {
		t.Fatal("accepted unauthenticated upstream")
	}
}

func TestHelperFraming(t *testing.T) {
	var encoded bytes.Buffer
	if err := writeFrame(&encoded, frame{Type: "ping"}); err != nil {
		t.Fatal(err)
	}
	var got frame
	if err := readFrame(bufio.NewReaderSize(&encoded, maxFrame), &got); err != nil || got.Type != "ping" {
		t.Fatalf("roundtrip: %+v %v", got, err)
	}
	for _, data := range []string{
		`{"version":99,"type":"ping"}` + "\n",
		`{"version":1,"type":"attach","attach":{"process":{"pid":1}}}` + "\n",
		fmt.Sprintf(`{"version":%d,"type":"ping","unexpected":"value"}`, ProtocolVersion) + "\n",
		fmt.Sprintf(`{"version":%d,"type":"ping"} {}`, ProtocolVersion) + "\n",
		strings.Repeat("x", maxFrame+1) + "\n",
	} {
		if err := readFrame(bufio.NewReaderSize(strings.NewReader(data), maxFrame), &frame{}); err == nil {
			t.Fatal("accepted invalid frame")
		}
	}
}
