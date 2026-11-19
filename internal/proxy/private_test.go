package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
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
