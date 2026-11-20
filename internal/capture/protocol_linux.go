package capture

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/qy/easyconnect/internal/netpolicy"
	"github.com/qy/easyconnect/internal/resolved"
	"github.com/qy/easyconnect/internal/workeripc"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
)

const (
	// Version 9 enforces worker DNS pool constraints before system updates.
	ProtocolVersion = 9
	maxFrame        = 64 << 10
	maxSessions     = 16
	LauncherFlag    = "--managed-capture-program"
)

var sessionPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

// Upstream is an authenticated, private SOCKS listener belonging to the GUI.
// It is sent over the UID-restricted control socket and never journalled.
type Upstream struct {
	Address  string            `json:"address"`
	Username string            `json:"username"`
	Password string            `json:"password"`
	DNS      *resolved.Config  `json:"dns,omitempty"`
	Networks []netpolicy.Range `json:"networks,omitempty"`
	Alias    *AliasRef         `json:"alias,omitempty"`
}

func (u Upstream) validate() error {
	host, port, err := net.SplitHostPort(u.Address)
	p, perr := strconv.Atoi(port)
	if err != nil || perr != nil || host != "127.0.0.1" || p < 1024 || p > 65535 {
		return errors.New("capture: upstream must be an unprivileged IPv4 loopback port")
	}
	if len(u.Username) < 1 || len(u.Username) > 128 || len(u.Password) < 32 || len(u.Password) > 128 {
		return errors.New("capture: private SOCKS authentication is required")
	}
	if err := netpolicy.Validate(u.Networks); err != nil {
		return err
	}
	if u.Alias != nil && (u.DNS == nil || !sessionPattern.MatchString(u.Alias.ID) || len(u.Alias.Token) != 64) {
		return errors.New("capture: invalid shared DNS reference")
	}
	if u.DNS != nil {
		return u.DNS.Validate()
	}
	return nil
}

// AliasRef is a capability shared only by launches from the same GUI/VPN
// generation. The helper still checks the socket's operating-system UID.
type AliasRef struct {
	ID    string `json:"id"`
	Token string `json:"token"`
}

type aliasRequest struct {
	DNS      resolved.Config   `json:"dns"`
	Networks []netpolicy.Range `json:"networks,omitempty"`
	Reserved []string          `json:"reserved,omitempty"`
}

type attachRequest struct {
	ID        string   `json:"id"`
	PID       int      `json:"pid"`
	StartTime uint64   `json:"startTime"`
	Upstream  Upstream `json:"upstream"`
}

type frame struct {
	Version  int                  `json:"version"`
	Type     string               `json:"type"`
	Token    string               `json:"token,omitempty"`
	Attach   *attachRequest       `json:"attach,omitempty"`
	ID       string               `json:"id,omitempty"`
	Active   bool                 `json:"active,omitempty"`
	Error    string               `json:"error,omitempty"`
	Alias    *aliasRequest        `json:"alias,omitempty"`
	Prefix   string               `json:"prefix,omitempty"`
	Mappings []workeripc.DNSAlias `json:"mappings,omitempty"`
	System   *SystemConfig        `json:"system,omitempty"`
	State    *SystemState         `json:"systemState,omitempty"`
}

func readFrame(r *bufio.Reader, v any) error {
	b, err := r.ReadSlice('\n')
	if err != nil {
		return err
	}
	if len(b) > maxFrame {
		return errors.New("capture: oversized message")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return errors.New("capture: invalid message")
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("capture: trailing message data")
	}
	return nil
}

func writeFrame(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b)+1 > maxFrame {
		return errors.New("capture: oversized message")
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

func RuntimeDir(uid int) string { return fmt.Sprintf("/run/easyconnect-hub-capture-%d", uid) }
func SocketPath(uid int) string { return RuntimeDir(uid) + "/control.sock" }

func scopePath(uid int, id string) string {
	return fmt.Sprintf("user.slice/user-%d.slice/user@%d.service/app.slice/easyconnect-hub-%s.scope", uid, uid, id)
}

func validScope(uid int, id, path string) bool {
	return uid > 0 && sessionPattern.MatchString(id) && path == scopePath(uid, id) && !strings.Contains(path, "..")
}
