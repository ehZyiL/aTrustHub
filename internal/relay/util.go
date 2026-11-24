package relay

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"net"
)

// randRead fills b from crypto/rand.
func randRead(b []byte) (int, error) { return rand.Read(b) }

// base64URL encodes one token without padding.
func base64URL(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// bufioReader wraps a connection for response parsing. The wrapper keeps any
// bytes it read ahead so the tunnel does not lose them.
func bufioReader(conn net.Conn) *bufio.Reader { return bufio.NewReader(conn) }
