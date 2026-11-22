package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

const (
	socks4CmdConnect = 1
	socks4CmdBind    = 2

	socks4RespGranted  = 90
	socks4RespRejected = 91
)

// handleSOCKS4 handles incoming SOCKS4 and SOCKS4a connection requests.
func (s *Server) handleSOCKS4(conn net.Conn, br *bufio.Reader) {
	vn, err := br.ReadByte()
	if err != nil {
		return
	}
	if vn != 4 {
		_ = s.replySOCKS4(conn, socks4RespRejected)
		return
	}
	cd, err := br.ReadByte()
	if err != nil {
		return
	}
	if cd != socks4CmdConnect {
		_ = s.replySOCKS4(conn, socks4RespRejected)
		s.logf("socks4: unsupported command %d", cd)
		return
	}
	var port uint16
	if err := binary.Read(br, binary.BigEndian, &port); err != nil {
		return
	}
	ip := make([]byte, 4)
	if _, err := io.ReadFull(br, ip); err != nil {
		return
	}
	// Read USERID (up to null byte, bounded to 256 bytes)
	_, err = readCString(br, 256)
	if err != nil {
		_ = s.replySOCKS4(conn, socks4RespRejected)
		return
	}

	target := ""
	// SOCKS4a extension: if IP is 0.0.0.x with non-zero x, hostname follows
	if ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0 {
		domain, err := readCString(br, 512)
		if err != nil || domain == "" {
			_ = s.replySOCKS4(conn, socks4RespRejected)
			return
		}
		target = net.JoinHostPort(domain, strconv.Itoa(int(port)))
	} else {
		target = net.JoinHostPort(net.IP(ip).String(), strconv.Itoa(int(port)))
	}

	parent := s.opts.Context
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, 45*time.Second)
	defer cancel()
	remote, err := s.dialFunc()(ctx, "tcp", target)
	if err != nil {
		_ = s.replySOCKS4(conn, socks4RespRejected)
		s.logf("socks4 dial %s: %v", target, err)
		return
	}
	if !s.track(remote) {
		_ = remote.Close()
		_ = s.replySOCKS4(conn, socks4RespRejected)
		return
	}
	defer func() {
		s.untrack(remote)
		_ = remote.Close()
	}()

	if err := s.replySOCKS4(conn, socks4RespGranted); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	pipe(bufferedConn{Conn: conn, r: br}, remote)
}

func (s *Server) replySOCKS4(conn net.Conn, code byte) error {
	resp := [8]byte{0x00, code, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	_, err := conn.Write(resp[:])
	return err
}

func readCString(br *bufio.Reader, limit int) (string, error) {
	var buf bytes.Buffer
	for i := 0; i < limit; i++ {
		b, err := br.ReadByte()
		if err != nil {
			return "", err
		}
		if b == 0 {
			return buf.String(), nil
		}
		buf.WriteByte(b)
	}
	return "", fmt.Errorf("c-string exceeded limit %d", limit)
}
