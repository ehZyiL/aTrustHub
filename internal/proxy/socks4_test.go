package proxy

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestSOCKS4Connect(t *testing.T) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()

	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyAddr := proxyLn.Addr().String()
	_ = proxyLn.Close()

	srv := New(Options{
		Addr: proxyAddr,
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	})
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	// Connect through proxy using SOCKS4
	conn, err := net.Dial("tcp", srv.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	echoPort := echoLn.Addr().(*net.TCPAddr).Port
	req := []byte{
		0x04,                   // VN: SOCKS4
		0x01,                   // CD: CONNECT
		byte(echoPort >> 8),   // Port high
		byte(echoPort & 0xff), // Port low
		127, 0, 0, 1,           // IP: 127.0.0.1
		0x00,                   // USERID: empty
	}
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}

	resp := make([]byte, 8)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}
	if resp[0] != 0x00 || resp[1] != 90 {
		t.Fatalf("socks4 rejected: %v", resp)
	}

	// Test payload roundtrip
	msg := []byte("hello socks4")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("got %q, want %q", string(buf), string(msg))
	}
}

func TestSOCKS4aConnectDomain(t *testing.T) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()

	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyAddr := proxyLn.Addr().String()
	_ = proxyLn.Close()

	echoPort := echoLn.Addr().(*net.TCPAddr).Port
	srv := New(Options{
		Addr: proxyAddr,
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// SOCKS4a should pass "localhost:port"
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	})
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	conn, err := net.Dial("tcp", srv.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// SOCKS4a: IP 0.0.0.1, followed by userid\0 and hostname\0
	req := []byte{
		0x04,
		0x01,
		byte(echoPort >> 8),
		byte(echoPort & 0xff),
		0, 0, 0, 1, // 0.0.0.x triggers 4a
		'u', 's', 'e', 'r', 0x00, // USERID
		'1', '2', '7', '.', '0', '.', '0', '.', '1', 0x00, // HOSTNAME
	}
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}

	resp := make([]byte, 8)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}
	if resp[0] != 0x00 || resp[1] != 90 {
		t.Fatalf("socks4a rejected: %v", resp)
	}

	msg := []byte("hello socks4a")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("got %q, want %q", string(buf), string(msg))
	}
}
