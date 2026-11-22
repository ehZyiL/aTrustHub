package proxy

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// N9: the handshake leaves bytes in its bufio.Reader (a client that sends its
// payload right behind CONNECT is common). The relay must read through that
// buffer, otherwise the first bytes of the tunnel are lost and the peer waits
// forever.
func TestHTTPConnectKeepsPipelinedBytes(t *testing.T) {
	echoAddr, closeEcho := echoServer(t)
	defer closeEcho()
	proxy := startProxy(t, Options{
		Addr: "127.0.0.1:0",
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.DialTimeout("tcp", echoAddr, 3*time.Second)
		},
	})
	conn, err := net.DialTimeout("tcp", proxy.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// One write: CONNECT headers and the payload in the same segment.
	request := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\nping"
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 39) // "HTTP/1.1 200 Connection established\r\n\r\n"
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read connect reply: %v", err)
	}
	// The echo server announces itself, then echoes what it received.
	hello := make([]byte, 5)
	if _, err := io.ReadFull(conn, hello); err != nil {
		t.Fatalf("read echo banner: %v", err)
	}
	if string(hello) != "echo:" {
		t.Fatalf("banner = %q", hello)
	}
	payload := make([]byte, 4)
	if _, err := io.ReadFull(conn, payload); err != nil {
		t.Fatalf("pipelined bytes were lost (the relay read around the handshake buffer): %v", err)
	}
	if string(payload) != "ping" {
		t.Fatalf("payload = %q, want %q", payload, "ping")
	}
}

// The same applies to SOCKS5: a client that pipelines data after the request must
// not lose it.
func TestSOCKS5KeepsPipelinedBytes(t *testing.T) {
	echoAddr, closeEcho := echoServer(t)
	defer closeEcho()
	proxy := startProxy(t, Options{
		Addr: "127.0.0.1:0",
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.DialTimeout("tcp", echoAddr, 3*time.Second)
		},
	})
	conn, err := net.DialTimeout("tcp", proxy.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Greeting + CONNECT to 10.0.0.1:80 + payload, all in one write. The dial
	// target is fixed by the test proxy, so the address only has to parse.
	packet := []byte{5, 1, 0}
	packet = append(packet, 5, 1, 0, 1, 10, 0, 0, 1, 0, 80)
	packet = append(packet, []byte("ping")...)
	if _, err := conn.Write(packet); err != nil {
		t.Fatal(err)
	}
	// method selection, then the CONNECT reply.
	if _, err := io.ReadFull(conn, make([]byte, 2)); err != nil {
		t.Fatalf("read method reply: %v", err)
	}
	if _, err := io.ReadFull(conn, make([]byte, 10)); err != nil {
		t.Fatalf("read connect reply: %v", err)
	}
	hello := make([]byte, 5)
	if _, err := io.ReadFull(conn, hello); err != nil {
		t.Fatalf("read echo banner: %v", err)
	}
	payload := make([]byte, 4)
	if _, err := io.ReadFull(conn, payload); err != nil {
		t.Fatalf("pipelined bytes were lost: %v", err)
	}
	if string(payload) != "ping" {
		t.Fatalf("payload = %q", payload)
	}
}
