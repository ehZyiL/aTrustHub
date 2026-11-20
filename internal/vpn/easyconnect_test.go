package vpn

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"github.com/miekg/dns"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qy/easyconnect/internal/model"
	localproxy "github.com/qy/easyconnect/internal/proxy"
	"github.com/qy/easyconnect/internal/workeripc"
	socksproxy "golang.org/x/net/proxy"
)

// A real subprocess exercises the same pipes and lifetime as the shipped worker.
func init() {
	mode := os.Getenv("EASYCONNECT_TEST_WORKER")
	if mode == "" {
		return
	}
	decoder, encoder := json.NewDecoder(os.Stdin), json.NewEncoder(os.Stdout)
	var start workeripc.Message
	if decoder.Decode(&start) != nil || start.Config == nil {
		os.Exit(2)
	}
	if mode == "silent-startup-exit" {
		os.Exit(1)
	}
	var writer sync.Mutex
	emit := func(m workeripc.Message) {
		writer.Lock()
		defer writer.Unlock()
		m.Version, m.Session = workeripc.Version, start.Session
		_ = encoder.Encode(m)
	}
	emit(workeripc.Message{Type: "challenge", Kind: "totp", ChallengeID: "one"})
	var answer workeripc.Message
	if decoder.Decode(&answer) != nil {
		os.Exit(0)
	}
	if mode == "crash" {
		os.Exit(3)
	}
	if answer.Answer != "test-code" || answer.ChallengeID != "one" {
		os.Exit(4)
	}
	if mode == "flows" {
		runFlowWorkerFixture(start, decoder, emit)
		os.Exit(0)
	}
	if mode == "prepared-flows" {
		runPreparedWorkerFixture(start, decoder, emit)
		os.Exit(0)
	}
	server := localproxy.New(localproxy.Options{Addr: "127.0.0.1:0", Auth: &localproxy.Auth{Username: start.Config.SocksUser, Credential: start.Config.SocksPassword}, Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr != "private.invalid:80" {
			return nil, errors.New("hostname lost before reaching worker")
		}
		left, right := net.Pipe()
		go func() {
			defer right.Close()
			_, _ = http.ReadRequest(bufio.NewReader(right))
			_, _ = io.WriteString(right, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
		}()
		return left, nil
	}})
	if server.Start() != nil {
		os.Exit(5)
	}
	emit(workeripc.Message{Type: "ready", Address: server.Addr().String(), ClientIP: "10.0.0.2", Resources: &workeripc.ResourceSnapshot{Tunnel: "tcp", DNSServer: "10.0.0.53", InternalDomains: []string{"corp.test"}}})
	var replies sync.WaitGroup
	for decoder.Decode(&answer) == nil {
		if answer.Type == "dns_query" && strings.HasPrefix(mode, "dns-alias") {
			q := new(dns.Msg)
			if q.Unpack(answer.DNS) != nil {
				os.Exit(6)
			}
			if !answer.CaptureDNS || answer.CapturePrefix != "198.19.64.0/20" {
				os.Exit(7)
			}
			m := new(dns.Msg).SetReply(q)
			m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.ParseIP("198.19.64.2")}}
			aliases := []workeripc.DNSAlias{{Address: "198.19.64.2", Original: "10.90.0.9", TTL: 30}}
			if mode == "dns-alias-wrong" {
				aliases[0].Address = "198.19.64.3"
			}
			packet, _ := m.Pack()
			emit(workeripc.Message{Type: "dns_result", RequestID: answer.RequestID, DNS: packet, DNSAliases: aliases})
		}
		if answer.Type == "dns_query" && mode == "dns" {
			request := answer
			request.DNS = append([]byte(nil), answer.DNS...)
			replies.Add(1)
			go func() {
				defer replies.Done()
				q := new(dns.Msg)
				if q.Unpack(request.DNS) != nil {
					return
				}
				time.Sleep(time.Duration(q.Id%5+1) * time.Millisecond)
				m := new(dns.Msg).SetRcode(q, dns.RcodeNameError)
				packet, _ := m.Pack()
				emit(workeripc.Message{Type: "dns_result", RequestID: request.RequestID, DNS: packet})
			}()
		}
		if answer.Type == "dns_query" && mode == "dns-exit" {
			os.Exit(0)
		}
	}
	replies.Wait()
	_ = server.Close()
	os.Exit(0)
}

func TestEasyConnectWorkerRoundtripAndLifetime(t *testing.T) {
	t.Setenv("EASYCONNECT_TEST_WORKER", "ready")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sess, err := NewEasyConnectConnector(exe)(ctx, model.AccessPoint{Server: "gateway.invalid", Port: 443}, Credentials{Login: "test-password", Challenge: func(_ context.Context, ch Challenge) (string, error) {
		if ch.Kind != "totp" {
			t.Fatal(ch.Kind)
		}
		return "test-code", nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	cancel() // authentication context must not terminate the online session
	public := localproxy.New(localproxy.Options{Addr: "127.0.0.1:0", Dial: sess.Dial})
	if err := public.Start(); err != nil {
		t.Fatal(err)
	}
	defer public.Close()
	for _, scheme := range []string{"http", "socks5"} {
		t.Run(scheme, func(t *testing.T) {
			transport := &http.Transport{}
			defer transport.CloseIdleConnections()
			if scheme == "http" {
				u, _ := url.Parse("http://" + public.Addr().String())
				transport.Proxy = http.ProxyURL(u)
			} else {
				d, err := socksproxy.SOCKS5("tcp", public.Addr().String(), nil, &net.Dialer{})
				if err != nil {
					t.Fatal(err)
				}
				transport.DialContext = d.(socksproxy.ContextDialer).DialContext
			}
			resp, err := (&http.Client{Transport: transport, Timeout: 3 * time.Second}).Get("http://private.invalid/")
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != 200 || string(body) != "ok" {
				t.Fatalf("status %d", resp.StatusCode)
			}
		})
	}
	if err := sess.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := sess.Dial(context.Background(), "tcp", "private.invalid:80"); err == nil {
		t.Fatal("closed session dial succeeded")
	}
	select {
	case <-sess.(SessionWatcher).Done():
	default:
		t.Fatal("worker survived pipe EOF")
	}
}

func TestEasyConnectSilentStartupExitExplainsBundleMismatch(t *testing.T) {
	t.Setenv("EASYCONNECT_TEST_WORKER", "silent-startup-exit")
	exe, _ := os.Executable()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := NewEasyConnectConnector(exe)(ctx, model.AccessPoint{Server: "gateway.invalid", Port: 443}, Credentials{Login: "test-password"})
	if err == nil || !strings.Contains(err.Error(), "尚未完成协议握手") || !strings.Contains(err.Error(), "退出码 1") || !strings.Contains(err.Error(), "完整测试包") {
		t.Fatalf("silent exit lost actionable bundle diagnosis: %v", err)
	}
}

func TestEasyConnectWorkerCancellationAndCrash(t *testing.T) {
	exe, _ := os.Executable()
	for _, mode := range []string{"cancel", "crash"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("EASYCONNECT_TEST_WORKER", mode)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_, err := NewEasyConnectConnector(exe)(ctx, model.AccessPoint{Server: "gateway.invalid", Port: 443}, Credentials{Login: "test-password", Challenge: func(ctx context.Context, _ Challenge) (string, error) {
				if mode == "cancel" {
					cancel()
					return "", ctx.Err()
				}
				return "test-code", nil
			}})
			if err == nil {
				t.Fatal("expected failure")
			}
			if strings.Contains(err.Error(), "test-password") {
				t.Fatal("credential leaked")
			}
		})
	}
}

func TestEasyConnectTunnelProbe(t *testing.T) {
	exe, _ := os.Executable()
	t.Setenv("EASYCONNECT_TEST_WORKER", "dns")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sess, err := NewEasyConnectConnector(exe)(ctx, model.AccessPoint{Server: "gateway.invalid", Port: 443}, Credentials{
		Login: "test-password",
		Challenge: func(ctx context.Context, _ Challenge) (string, error) {
			return "test-code", nil
		},
	})
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer sess.Close()

	prober, ok := sess.(Prober)
	if !ok {
		t.Fatal("processSession does not implement Prober")
	}

	probeCtx, pCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer pCancel()
	if err := prober.Probe(probeCtx); err != nil {
		t.Fatalf("probe failed on healthy session: %v", err)
	}

	_ = sess.Close()
	if err := prober.Probe(probeCtx); err == nil {
		t.Fatal("probe succeeded on closed session, want error")
	}
}
