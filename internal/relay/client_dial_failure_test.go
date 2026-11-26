package relay

import (
	"errors"
	"net"
	"strings"
	"testing"
)

// The colleague must be told something actionable when the host is gone. These
// are the real texts both platforms produce: Unix says "connection refused",
// Windows says "actively refused it", and a filtered path times out instead.
func TestDescribeHostDialFailure(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want string
	}{
		{`Post "https://192.168.201.135:58501/v1/sessions": dial tcp 192.168.201.135:58501: connect: connection refused`,
			"分享主机拒绝了连接：共享可能已关闭，或宿主已退出"},
		{`dial tcp 192.168.201.135:58501: connectex: No connection could be made because the target machine actively refused it.`,
			"分享主机拒绝了连接：共享可能已关闭，或宿主已退出"},
		{`dial tcp 192.168.201.135:58501: connect: no route to host`,
			"分享主机不可达：双方不在同一网段，或宿主的网络被系统归为「公用」/防火墙未放行"},
		{`dial tcp 192.168.201.135:58501: connect: network is unreachable`,
			"分享主机不可达：双方不在同一网段，或宿主的网络被系统归为「公用」/防火墙未放行"},
		{`read tcp 192.168.201.135:1234->192.168.201.135:58501: read: connection reset by peer`,
			"分享主机重置了连接"},
		{`dial tcp 192.168.201.135:58501: i/o timeout`, "连接分享主机超时"},
		{`something unexpected`, "无法连接分享主机"},
	} {
		got := describeHostDialFailure(errors.New(tc.raw))
		if got != tc.want {
			t.Fatalf("describeHostDialFailure(%q) = %q, want %q", tc.raw, got, tc.want)
		}
		// The sentence must stand on its own: no raw URL, no Go verb prefix.
		for _, leak := range []string{"dial tcp", "Post ", "https://", "connectex"} {
			if strings.Contains(got, leak) {
				t.Fatalf("原因里仍然带着原始错误片段 %q：%q", leak, got)
			}
		}
	}
}

// End to end through the protocol error, so the message a caller sees is the
// classified one and not a wrapped transport string.
func TestClosedShareReportsAHostRefusal(t *testing.T) {
	// A port that is guaranteed to be closed: bind, note it, release it.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	_ = ln.Close()

	code := ShareCode{Version: 1, Host: "192.168.1.50", Port: 23456,
		Fingerprint: strings.Repeat("ab", 32)}
	code.Host = "127.0.0.1"
	code.Port = addr.Port
	client, err := NewClient(ClientOptions{Code: code})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()
	_, _, err = client.Open(t.Context())
	var re *Error
	if !errors.As(err, &re) {
		t.Fatalf("want a protocol error, got %v", err)
	}
	if re.Code != CodeTargetUnreachable {
		t.Fatalf("code = %s, want %s", re.Code, CodeTargetUnreachable)
	}
	if !strings.Contains(re.Message, "分享主机拒绝了连接") {
		t.Fatalf("message = %q", re.Message)
	}
}
