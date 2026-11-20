package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	xproxy "golang.org/x/net/proxy"
)

func TestPrivateSOCKSRejectsHTTPBeforeDial(t *testing.T) {
	var calls atomic.Int64
	s := New(Options{Addr: "127.0.0.1:0", SOCKSOnly: true, Auth: &Auth{Username: "private", Credential: "secret"}, Dial: func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		return nil, errors.New("must not dial")
	}})
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c, err := net.DialTimeout("tcp", s.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	io.WriteString(c, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("HTTP request accepted on private SOCKS")
	}
	if calls.Load() != 0 {
		t.Fatal("HTTP bypassed SOCKS authentication")
	}
}

func TestPrivateDatagramsRequireExplicitListenerAndCredentials(t *testing.T) {
	var calls atomic.Int64
	dial := func(context.Context, string) (net.Conn, error) {
		calls.Add(1)
		return nil, errors.New("fixture refuses target")
	}
	opts := Options{Addr: "127.0.0.1:0", Auth: &Auth{Username: "helper", Credential: "fixture-secret"},
		Dial: func(ctx context.Context, _ string, address string) (net.Conn, error) { return dial(ctx, address) }, DialDatagram: dial}
	public := New(opts)
	if err := public.Start(); err == nil {
		public.Close()
		t.Fatal("mixed listener accepted the private datagram extension")
	}
	opts.SOCKSOnly = true
	for _, tc := range []struct {
		name, password string
		enabled        bool
		wantDials      int64
	}{
		{"tcp only", opts.Auth.Credential, false, 0},
		{"bad credentials", "wrong", true, 0},
		{"refused location", opts.Auth.Credential, true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := opts
			if !tc.enabled {
				config.DialDatagram = nil
			}
			s := New(config)
			if err := s.Start(); err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			d, err := NewSOCKSDialer(s.Addr().String(), &xproxy.Auth{User: opts.Auth.Username, Password: tc.password})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			before := calls.Load()
			if c, err := d.DialDatagramContext(ctx, "192.0.2.21:9000"); err == nil {
				c.Close()
				t.Fatal("datagram link unexpectedly accepted")
			}
			if got := calls.Load() - before; got != tc.wantDials {
				t.Fatalf("dial calls: %d, want %d", got, tc.wantDials)
			}
		})
	}
}
