package vpn

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/qy/easyconnect/internal/model"
	"github.com/qy/easyconnect/internal/workeripc"
	"github.com/things-go/go-socks5"
)

type strictFixtureResolver struct{}

func (strictFixtureResolver) Resolve(ctx context.Context, _ string) (context.Context, net.IP, error) {
	return ctx, nil, nil
}

func runPreparedWorkerFixture(start workeripc.Message, decoder *json.Decoder, emit func(workeripc.Message)) {
	var mu sync.Mutex
	prepared := make(map[string]int64)
	listen := func(route string) net.Listener {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			os.Exit(5)
		}
		server := socks5.NewServer(socks5.WithResolver(strictFixtureResolver{}), socks5.WithAuthMethods([]socks5.Authenticator{socks5.UserPassAuthenticator{Credentials: testFlowCredentials{start.Config.SocksPassword}}}), socks5.WithDialAndRequest(func(_ context.Context, _, address string, req *socks5.Request) (net.Conn, error) {
			id := testFlowID(req)
			mu.Lock()
			deadline := prepared[id]
			delete(prepared, id)
			mu.Unlock()
			if deadline <= time.Now().UnixMilli() {
				return nil, errors.New("missing preparation")
			}
			result := workeripc.FlowResult{Target: address, Route: route, Rule: "default"}
			if route == "vpn" {
				result.Rule = "forced"
			}
			emit(workeripc.Message{Type: "flow_result", RequestID: id, Flow: &result})
			a, b := net.Pipe()
			go func() { defer b.Close(); io.WriteString(b, route) }()
			return testAddrConn{a}, nil
		}))
		go server.Serve(ln)
		return ln
	}
	ordinary, strict := listen("direct"), listen("vpn")
	defer ordinary.Close()
	defer strict.Close()
	emit(workeripc.Message{Type: "ready", Address: ordinary.Addr().String(), VPNAddress: strict.Addr().String(), FlowReporting: true, Capabilities: []string{"strict_vpn", "flow_cancel", "flow_prepare"}})
	var message workeripc.Message
	for decoder.Decode(&message) == nil {
		mu.Lock()
		switch message.Type {
		case "flow_prepare":
			prepared[message.RequestID] = message.Deadline
		case "flow_cancel":
			delete(prepared, message.RequestID)
		}
		mu.Unlock()
		if message.Type == "flow_prepare" {
			emit(workeripc.Message{Type: "flow_ready", RequestID: message.RequestID})
		}
	}
}

func TestPreparedFlowUsesSeparateOrdinaryAndStrictEntrypoints(t *testing.T) {
	t.Setenv("EASYCONNECT_TEST_WORKER", "prepared-flows")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	sess, err := NewEasyConnectConnector(exe)(context.Background(), model.AccessPoint{Server: "fixture.invalid", Port: 443}, Credentials{Login: "test-only", Challenge: func(context.Context, Challenge) (string, error) { return "test-code", nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	for _, strict := range []bool{false, true, false, true} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		var conn net.Conn
		want := "direct"
		if strict {
			conn, err = sess.(StrictSession).DialVPN(ctx, "tcp", "private.test:443")
			want = "vpn"
		} else {
			conn, err = sess.Dial(ctx, "tcp", "public.test:443")
		}
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(time.Second))
		payload, readErr := io.ReadAll(conn)
		conn.Close()
		if readErr != nil || string(payload) != want {
			t.Fatalf("want %s, got %q %v", want, payload, readErr)
		}
		if result := workeripc.ConnectionResult(conn, nil); result.Route != want {
			t.Fatalf("wrong reported path: %+v", result)
		}
	}
}
