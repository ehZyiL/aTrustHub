package relay

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"time"
)

// Dialer dials the original network. The relay never uses the system proxy, the
// app's Manager or an environment-configured proxy: a control channel that goes
// through the tunnel it manages would recurse.
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

// DirectDialer dials without any proxy, still honoring the context deadline.
func DirectDialer(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

// ClientTransportOptions builds the pinned TLS transport a sharing client uses.
type ClientTransportOptions struct {
	Fingerprint string
	Host        string
	Dial        Dialer
}

// NewClientTransport returns an http.Transport that
//   - never uses a proxy (Proxy is explicitly nil),
//   - dials through the injected original-network Dialer,
//   - pins the share's leaf certificate.
//
// The transport is safe to share between the control client and CONNECT.
func NewClientTransport(opts ClientTransportOptions) (*http.Transport, error) {
	tlsConfig, err := ClientTLSConfig(opts.Fingerprint, opts.Host)
	if err != nil {
		return nil, err
	}
	dial := opts.Dial
	if dial == nil {
		dial = DirectDialer
	}
	transport := &http.Transport{
		// Explicitly nil: no proxy environment variable may hijack the tunnel.
		Proxy:                 nil,
		DialContext:           dial,
		DialTLSContext:        nil,
		TLSClientConfig:       tlsConfig,
		TLSHandshakeTimeout:   TLSHandshakeTimeout,
		DisableKeepAlives:     false,
		MaxIdleConns:          8,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: time.Second,
		ForceAttemptHTTP2:     false,
		TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	return transport, nil
}

// bufferedConn keeps the bytes a bufio.Reader already pulled off the socket.
// Losing them would corrupt the first request of every Hijacked tunnel.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// WrapBuffered returns a connection whose reads first drain r. When r holds
// nothing buffered it is the plain connection.
func WrapBuffered(conn net.Conn, r *bufio.Reader) net.Conn {
	if r == nil || r.Buffered() == 0 {
		return conn
	}
	return &bufferedConn{Conn: conn, r: r}
}

// CloseWrite half-closes when the underlying connection supports it, so a
// bounded half-close is preserved instead of turning into a hard reset.
func CloseWrite(conn net.Conn) error {
	type closeWriter interface{ CloseWrite() error }
	if cw, ok := conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return nil
}

// ignoreEOF turns a clean EOF into a nil error for relay loops.
func ignoreEOF(err error) error {
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}
