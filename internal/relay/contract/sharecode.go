package contract

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ShareCode scheme. The only accepted form is
//
//	connect-hub://relay/v1#<base64url-json>
const (
	ShareScheme    = "connect-hub"
	ShareAuthority = "relay"
	SharePath      = "/v1"
	ShareVersion   = 1

	// MaxShareCodeBytes bounds the whole pasted text.
	MaxShareCodeBytes = 8 << 10
	// MaxShareCodeJSON bounds the decoded payload.
	MaxShareCodeJSON = 4 << 10
	// MaxShareNameRunes bounds the optional display name.
	MaxShareNameRunes = 80
)

// ShareCode is a parsed v1 share code: where the sharing host listens, which
// share it is, the bearer token and the pinned certificate fingerprint.
type ShareCode struct {
	Version     int    `json:"v"`
	Host        string `json:"h"`
	Port        int    `json:"p"`
	ShareID     string `json:"sid"`
	Token       string `json:"token"`
	Fingerprint string `json:"fp"`
	Name        string `json:"name,omitempty"`
}

// Address is the host:port the share code points at.
func (c ShareCode) Address() string { return net.JoinHostPort(c.Host, itoa(c.Port)) }

func itoa(n int) string {
	var buf [20]byte
	i := len(buf)
	if n == 0 {
		return "0"
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// DisplayName is the name to show in a preview, falling back to the address.
func (c ShareCode) DisplayName() string {
	if strings.TrimSpace(c.Name) != "" {
		return c.Name
	}
	return c.Address()
}

// String rebuilds the canonical share code. It is used for copy and for the
// QR payload, so both carry exactly the same text.
func (c ShareCode) String() string {
	payload := struct {
		V     int    `json:"v"`
		H     string `json:"h"`
		P     int    `json:"p"`
		SID   string `json:"sid"`
		Token string `json:"token"`
		FP    string `json:"fp"`
		Name  string `json:"name,omitempty"`
	}{c.Version, c.Host, c.Port, c.ShareID, c.Token, c.Fingerprint, c.Name}
	b, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	return ShareScheme + "://" + ShareAuthority + SharePath + "#" + base64.RawURLEncoding.EncodeToString(b)
}

// ErrNotShareCode says the text is not a share code at all, so callers can treat
// it as ordinary clipboard content without alarming the user.
var ErrNotShareCode = errors.New("不是分享口令")

// ParseShareCode parses text strictly. Preview never touches the network.
//
// It rejects padding, unknown or duplicate keys, trailing JSON, wrong types,
// overflowed integers, non-RFC1918 hosts, control characters and anything over
// the size limits. Only the exact scheme/authority/path is accepted, and
// userinfo or a query is refused.
func ParseShareCode(text string) (ShareCode, error) {
	var code ShareCode
	if len(text) > MaxShareCodeBytes {
		return code, fmt.Errorf("%w：口令超过 %d 字节", ErrNotShareCode, MaxShareCodeBytes)
	}
	s := strings.TrimSpace(text)
	if s == "" {
		return code, ErrNotShareCode
	}
	prefix := ShareScheme + "://"
	if !strings.HasPrefix(strings.ToLower(s), prefix) {
		return code, ErrNotShareCode
	}
	rest := s[len(prefix):]
	// The fragment is the payload; anything before it must be exactly the
	// authority and path.
	hash := strings.IndexByte(rest, '#')
	if hash < 0 || hash+1 >= len(rest) {
		return code, fmt.Errorf("%w：缺少分享载荷", ErrNotShareCode)
	}
	prefixPart, payload := rest[:hash], rest[hash+1:]
	if prefixPart != ShareAuthority+SharePath {
		return code, fmt.Errorf("%w：只支持 %s://%s%s", ErrNotShareCode, ShareScheme, ShareAuthority, SharePath)
	}
	if strings.ContainsAny(payload, "=&?/ ") {
		return code, fmt.Errorf("%w：载荷只允许 Base64URL 字符", ErrNotShareCode)
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return code, fmt.Errorf("%w：Base64URL 无效（不允许填充或非法字符）", ErrNotShareCode)
	}
	if len(raw) > MaxShareCodeJSON {
		return code, fmt.Errorf("%w：载荷超过 %d 字节", ErrNotShareCode, MaxShareCodeJSON)
	}
	if err := parseSharePayload(raw, &code); err != nil {
		return code, err
	}
	return code, nil
}

// parseSharePayload decodes one flat JSON object with an explicit duplicate and
// type check. json.Unmarshal alone silently keeps the last of duplicate keys,
// which turns an ambiguous input into a trusted credential.
func parseSharePayload(raw []byte, out *ShareCode) error {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return fmt.Errorf("%w：载荷必须是 JSON 对象", ErrNotShareCode)
	}
	seen := map[string]bool{}
	var names []string
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("%w：JSON 无法解析", ErrNotShareCode)
		}
		key, ok := tok.(string)
		if !ok {
			return fmt.Errorf("%w：JSON 键无效", ErrNotShareCode)
		}
		if seen[key] {
			return fmt.Errorf("%w：字段 %q 重复", ErrNotShareCode, key)
		}
		seen[key] = true
		names = append(names, key)
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return fmt.Errorf("%w：字段 %q 无法解析", ErrNotShareCode, key)
		}
		if err := assignShareField(key, value, out); err != nil {
			return err
		}
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return fmt.Errorf("%w：JSON 对象未闭合", ErrNotShareCode)
	}
	// Reject trailing content: a second object must not be ignored.
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("%w：载荷包含尾随内容", ErrNotShareCode)
	}
	// Required fields. v1 has no optional identity fields besides name.
	for _, required := range []string{"v", "h", "p", "sid", "token", "fp"} {
		if !seen[required] {
			return fmt.Errorf("%w：缺少字段 %q", ErrNotShareCode, required)
		}
	}
	return validateShareCode(out)
}

func assignShareField(key string, value json.RawMessage, out *ShareCode) error {
	switch key {
	case "v":
		n, err := shareInt(value)
		if err != nil {
			return err
		}
		if n != ShareVersion {
			return fmt.Errorf("%w：分享协议版本 %d 不受支持", ErrNotShareCode, n)
		}
		out.Version = n
	case "p":
		n, err := shareInt(value)
		if err != nil {
			return err
		}
		if n < 1 || n > 65535 {
			return fmt.Errorf("%w：端口必须在 1–65535 之间", ErrNotShareCode)
		}
		out.Port = n
	case "h":
		s, err := shareString(value)
		if err != nil {
			return err
		}
		out.Host = s
	case "sid":
		s, err := shareString(value)
		if err != nil {
			return err
		}
		out.ShareID = s
	case "token":
		s, err := shareString(value)
		if err != nil {
			return err
		}
		out.Token = s
	case "fp":
		s, err := shareString(value)
		if err != nil {
			return err
		}
		out.Fingerprint = s
	case "name":
		s, err := shareString(value)
		if err != nil {
			return err
		}
		out.Name = s
	default:
		return fmt.Errorf("%w：未知字段 %q", ErrNotShareCode, key)
	}
	return nil
}

func shareString(raw json.RawMessage) (string, error) {
	trimmed := strings.TrimSpace(string(raw))
	if !strings.HasPrefix(trimmed, "\"") {
		return "", fmt.Errorf("%w：字段必须是字符串", ErrNotShareCode)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", fmt.Errorf("%w：字符串字段无效", ErrNotShareCode)
	}
	return s, nil
}

// shareInt accepts only a plain JSON integer. json.Number keeps the literal, so
// "1.0", "1e3", a string and an overflowed value are all refused instead of
// being rounded into a valid-looking port.
func shareInt(raw json.RawMessage) (int, error) {
	num := json.Number(strings.TrimSpace(string(raw)))
	s := num.String()
	if s == "" {
		return 0, fmt.Errorf("%w：字段必须是整数", ErrNotShareCode)
	}
	negative := false
	if s[0] == '-' {
		negative = true
		s = s[1:]
	}
	if s == "" {
		return 0, fmt.Errorf("%w：字段必须是整数", ErrNotShareCode)
	}
	value := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("%w：字段必须是整数", ErrNotShareCode)
		}
		value = value*10 + int(r-'0')
		if value > 1<<30 {
			return 0, fmt.Errorf("%w：整数溢出", ErrNotShareCode)
		}
	}
	if negative {
		value = -value
	}
	return value, nil
}

func validateShareCode(c *ShareCode) error {
	ip := net.ParseIP(c.Host)
	if ip == nil || ip.To4() == nil {
		return fmt.Errorf("%w：分享主机必须是 IPv4 地址", ErrNotShareCode)
	}
	v4 := ip.To4()
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || !privateIPv4(v4) {
		return fmt.Errorf("%w：分享主机必须是局域网（RFC1918）单播地址", ErrNotShareCode)
	}
	// The host must be a bare address: a port, path or userinfo would have
	// survived net.ParseIP only by accident.
	if strings.ContainsAny(c.Host, ":/?#@[] \\\t\r\n") {
		return fmt.Errorf("%w：分享主机不能包含端口或路径", ErrNotShareCode)
	}
	if !validBase64(c.ShareID, shareIDLen) {
		return fmt.Errorf("%w：分享 ID 格式无效", ErrNotShareCode)
	}
	if !validBase64(c.Token, shareTokenLen) {
		return fmt.Errorf("%w：分享口令格式无效", ErrNotShareCode)
	}
	if len(c.Fingerprint) != 64 {
		return fmt.Errorf("%w：证书指纹必须是 64 位十六进制", ErrNotShareCode)
	}
	for _, r := range c.Fingerprint {
		if !(r >= '0' && r <= '9') && !(r >= 'a' && r <= 'f') {
			return fmt.Errorf("%w：证书指纹只能是小写十六进制", ErrNotShareCode)
		}
	}
	if !utf8.ValidString(c.Name) {
		return fmt.Errorf("%w：显示名称不是有效 UTF-8", ErrNotShareCode)
	}
	count := 0
	for _, r := range c.Name {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w：显示名称不能包含控制字符", ErrNotShareCode)
		}
		count++
	}
	if count > MaxShareNameRunes {
		return fmt.Errorf("%w：显示名称最多 %d 个字符", ErrNotShareCode, MaxShareNameRunes)
	}
	return nil
}

const (
	shareIDLen    = 16
	shareTokenLen = 32
)

// validBase64 reports whether s is canonical unpadded Base64URL of n bytes.
func validBase64(s string, n int) bool {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) != n {
		return false
	}
	return base64.RawURLEncoding.EncodeToString(b) == s
}
