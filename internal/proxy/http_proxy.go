package proxy

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// handleHTTP serves one HTTP-proxy request on the same listener as SOCKS5.
// It supports CONNECT (HTTPS and any TCP) and absolute-URI forwarding.
func (s *Server) handleHTTP(conn net.Conn, br *bufio.Reader) {
	req, err := http.ReadRequest(br)
	if err != nil {
		s.logf("http: %v", err)
		return
	}
	// The proxy credential is hop-by-hop: never forward it to the destination.
	// It must be dropped before req.Write, so this cannot be a defer.
	if err := s.authorizeHTTP(req); err != nil {
		_, _ = io.WriteString(conn, "HTTP/1.1 407 Proxy Authentication Required\r\n"+
			"Proxy-Authenticate: Basic realm=\"Connect Hub\"\r\nContent-Length: 0\r\n\r\n")
		s.logf("http: %v", err)
		return
	}
	req.Header.Del("Proxy-Authorization")
	target := req.Host
	if req.Method == http.MethodConnect {
		if !strings.Contains(target, ":") {
			target += ":443"
		}
		remote, err := s.dial(target)
		if err != nil {
			_, _ = io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
			s.logf("http connect %s: %v", target, err)
			return
		}
		defer s.closeRemote(remote)
		if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
			return
		}
		_ = conn.SetDeadline(time.Time{})
		pipe(bufferedConn{Conn: conn, r: br}, remote)
		return
	}

	if !req.URL.IsAbs() || req.URL.Host == "" {
		_, _ = io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
		s.logf("http: not a proxy request")
		return
	}
	host := req.URL.Host
	if !strings.Contains(host, ":") {
		if req.URL.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	remote, err := s.dial(host)
	if err != nil {
		_, _ = io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		s.logf("http get %s: %v", host, err)
		return
	}
	defer s.closeRemote(remote)
	_ = conn.SetDeadline(time.Time{})
	// Rewrite the absolute-URI request to origin form for the server.
	req.RequestURI = ""
	req.Header.Del("Proxy-Connection")
	if err := req.Write(remote); err != nil {
		return
	}
	pipe(bufferedConn{Conn: conn, r: br}, remote)
}

// authorizeHTTP enforces the same credential the SOCKS5 listener asks for.
// Without it, setting Auth on a listener would leave the HTTP proxy wide open.
func (s *Server) authorizeHTTP(req *http.Request) error {
	auth := s.opts.Auth
	if auth == nil {
		return nil
	}
	header := req.Header.Get("Proxy-Authorization")
	if header == "" {
		return errors.New("missing proxy credentials")
	}
	scheme, encoded, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return errors.New("unsupported proxy authentication scheme")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return errors.New("malformed proxy credentials")
	}
	user, pass, ok := strings.Cut(string(raw), ":")
	if !ok {
		return errors.New("malformed proxy credentials")
	}
	userOK := subtle.ConstantTimeCompare([]byte(user), []byte(auth.Username)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(pass), []byte(auth.Credential)) == 1
	if !userOK || !passOK {
		return errors.New("bad proxy credentials")
	}
	return nil
}

func (s *Server) dial(target string) (net.Conn, error) {
	parent := s.opts.Context
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, 45*time.Second)
	defer cancel()
	remote, err := s.dialFunc()(ctx, "tcp", target)
	if err != nil {
		return nil, err
	}
	if !s.track(remote) {
		_ = remote.Close()
		return nil, fmt.Errorf("server closed")
	}
	return remote, nil
}

func (s *Server) closeRemote(remote net.Conn) {
	s.untrack(remote)
	_ = remote.Close()
}
