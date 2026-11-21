package vpn

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/ehZyiL/connect-hub/internal/model"
	"github.com/ehZyiL/connect-hub/internal/proxy"
	"github.com/ehZyiL/connect-hub/internal/workeripc"
)

// Uses the production Manager and proxy servers; only gateway sessions are fakes.
func TestResourceRouteExclusiveThroughProxy(t *testing.T) {
	for _, protocol := range []string{"socks5", "connect"} {
		for _, mode := range []model.Routing{model.RoutingHash, model.RoutingLatency, model.RoutingFailover} {
			for _, offline := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/failing=%v", protocol, mode, offline), func(t *testing.T) {
					a, b := newFakeSession("A"), newFakeSession("B")
					b.info.Resources = &workeripc.ResourceSnapshot{DomainRules: []workeripc.DomainRule{{Domain: "b.corp.test", PortMin: 443, PortMax: 443, Protocol: "tcp"}}}
					if offline {
						b.dialErr = errors.New("B unavailable")
					}
					cfg := testConfig(model.AccessPoint{ID: "a", Name: "A", InPool: true}, model.AccessPoint{ID: "b", Name: "B", InPool: true})
					cfg.Settings.Routing = mode
					m := newTestManager(t, nil, cfg)
					m.mu.Lock()
					for id, sess := range map[string]*fakeSession{"a": a, "b": b} {
						ep := m.points[id]
						ep.state, ep.sess, ep.info = StateOnline, sess, sess.Info()
					}
					m.mu.Unlock()
					server := proxy.New(proxy.Options{Addr: "127.0.0.1:0", Dial: m.Dial})
					if err := server.Start(); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { server.Close() })
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer cancel()
					conn, err := resourceProxyDial(ctx, protocol, server.Addr().String(), "b.corp.test:443")
					if conn != nil {
						defer conn.Close()
						conn.SetDeadline(time.Now().Add(time.Second))
						payload, readErr := io.ReadAll(conn)
						if !offline && (readErr != nil || string(payload) != "B") {
							t.Errorf("response=%q error=%v; want B", payload, readErr)
						}
					}
					if (err != nil) != offline {
						t.Errorf("dial error=%v; B failing=%v", err, offline)
					}
					a.mu.Lock()
					aCalls := len(a.dials)
					a.mu.Unlock()
					b.mu.Lock()
					bCalls := len(b.dials)
					b.mu.Unlock()
					if aCalls != 0 || bCalls != 1 {
						t.Fatalf("gateway calls A=%d B=%d; want A=0 B=1", aCalls, bCalls)
					}
				})
			}
		}
	}
}

func resourceProxyDial(ctx context.Context, protocol, address, target string) (net.Conn, error) {
	if protocol == "socks5" {
		d, err := proxy.NewSOCKSDialer(address, nil)
		if err != nil {
			return nil, err
		}
		return d.DialContext(ctx, "tcp", target)
	}
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	deadline, _ := ctx.Deadline()
	c.SetDeadline(deadline)
	if _, err = fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		c.Close()
		return nil, err
	}
	reader := bufio.NewReader(c)
	r, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil || r.StatusCode != http.StatusOK {
		c.Close()
		return nil, errors.New("CONNECT rejected")
	}
	return &resourceBufferedConn{Conn: c, reader: reader}, nil
}

type resourceBufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *resourceBufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
