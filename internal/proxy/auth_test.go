package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The LAN listener sets Auth. SOCKS4 has no authentication field, so it must be
// refused on such a listener instead of becoming a credential bypass.
func TestSOCKS4RejectedWhenAuthRequired(t *testing.T) {
	proxy := startProxy(t, Options{
		Addr: "127.0.0.1:0",
		Auth: &Auth{Username: "hub", Credential: "0123456789abcdef01234567"},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, context.DeadlineExceeded
		},
	})
	conn, err := net.DialTimeout("tcp", proxy.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	// SOCKS4 CONNECT to 1.2.3.4:80 with an empty user id.
	request := []byte{4, 1, 0, 80, 1, 2, 3, 4, 0}
	if _, err := conn.Write(request); err != nil {
		t.Fatal(err)
	}
	var reply [8]byte
	if _, err := io.ReadFull(conn, reply[:]); err == nil {
		t.Fatalf("SOCKS4 was answered on an authenticated listener: %v", reply)
	}
}

// SOCKS4 must keep working on the unauthenticated loopback listener: existing
// tools rely on it and the upgrade must not break them.
func TestSOCKS4StillServedWithoutAuth(t *testing.T) {
	echoAddr, closeEcho := echoServer(t)
	defer closeEcho()
	target, err := net.ResolveTCPAddr("tcp", echoAddr)
	if err != nil || target.IP.To4() == nil {
		t.Skip("no IPv4 echo address")
	}
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
	request := []byte{4, 1, byte(target.Port >> 8), byte(target.Port), target.IP[0], target.IP[1], target.IP[2], target.IP[3], 0}
	if _, err := conn.Write(request); err != nil {
		t.Fatal(err)
	}
	var reply [8]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		t.Fatalf("SOCKS4 reply: %v", err)
	}
	if reply[1] != 90 {
		t.Fatalf("SOCKS4 rejected the unauthenticated listener: %v", reply)
	}
}

func httpProxyRequest(t *testing.T, proxyAddr, request string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil && !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("read status line: %v", err)
	}
	return strings.TrimSpace(line)
}

func basicHeader(user, pass string) string {
	return "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass)) + "\r\n"
}

// The HTTP proxy shares the listener, so it must enforce the same credential;
// otherwise Auth would only protect SOCKS5.
func TestHTTPProxyRequiresCredentials(t *testing.T) {
	echoAddr, closeEcho := echoServer(t)
	defer closeEcho()
	const password = "0123456789abcdef01234567"
	proxy := startProxy(t, Options{
		Addr: "127.0.0.1:0",
		Auth: &Auth{Username: "hub", Credential: password},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.DialTimeout("tcp", echoAddr, 3*time.Second)
		},
	})
	addr := proxy.Addr().String()
	const connect = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n"

	if got := httpProxyRequest(t, addr, connect+"\r\n"); !strings.Contains(got, "407") {
		t.Fatalf("request without credentials = %q, want 407", got)
	}
	// A wrong password must not be accepted either.
	if got := httpProxyRequest(t, addr, connect+basicHeader("hub", "wrong-password-000000")+"\r\n"); !strings.Contains(got, "407") {
		t.Fatalf("request with a wrong password = %q, want 407", got)
	}
	if got := httpProxyRequest(t, addr, connect+basicHeader("hub", password)+"\r\n"); !strings.Contains(got, "200") {
		t.Fatalf("request with the right password = %q, want 200", got)
	}
}

// A plain forwarding request (absolute URI) must also be authenticated, and the
// proxy credential must not leak to the destination.
func TestHTTPForwardStripsProxyAuthorization(t *testing.T) {
	const password = "0123456789abcdef01234567"
	seen := make(chan string, 1)
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		conn, err := target.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			seen <- "unreadable request: " + err.Error()
			return
		}
		_ = req.Body.Close()
		// The proxy must rewrite absolute form to origin form and drop the
		// hop-by-hop credential.
		seen <- req.Method + " " + req.URL.RequestURI() + " auth=" + req.Header.Get("Proxy-Authorization")
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	}()
	proxy := startProxy(t, Options{
		Addr: "127.0.0.1:0",
		Auth: &Auth{Username: "hub", Credential: password},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.DialTimeout("tcp", target.Addr().String(), 3*time.Second)
		},
	})
	conn, err := net.DialTimeout("tcp", proxy.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	request := "GET http://example.test/page HTTP/1.1\r\nHost: example.test\r\n" + basicHeader("hub", password) + "\r\n"
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatal(err)
	}
	if status, err := bufio.NewReader(conn).ReadString('\n'); err != nil || !strings.Contains(status, "200") {
		t.Fatalf("status = %q, %v", status, err)
	}
	select {
	case got := <-seen:
		if !strings.HasPrefix(got, "GET /page ") {
			t.Fatalf("destination saw %q, want origin form", got)
		}
		if strings.Contains(strings.ToLower(got), "auth=basic") || strings.Contains(got, password) {
			t.Fatalf("proxy credential leaked to the destination: %q", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("destination received no request")
	}
}
