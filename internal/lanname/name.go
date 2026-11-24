// Package lanname holds the rules for the public alias a LAN share broadcasts.
// It is a leaf package so the configuration, the share controller and the
// discovery protocol can all enforce the same rule without depending on each
// other.
package lanname

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxRunes and MaxBytes bound the alias. The byte bound keeps the value inside
// the DNS-SD TXT budget even after multicast DNS escapes non-ASCII bytes.
const (
	MaxRunes = 40
	MaxBytes = 160
)

// Valid checks an alias as it will be broadcast. It runs on save, on publish
// and on receive, so a name that cannot travel unchanged is refused everywhere
// instead of being silently rewritten.
func Valid(name string) error {
	if name == "" {
		return errors.New("公开名称不能为空")
	}
	if !utf8.ValidString(name) {
		return errors.New("公开名称必须是合法文本")
	}
	if n := utf8.RuneCountInString(name); n > MaxRunes {
		return fmt.Errorf("公开名称最多 %d 个字符", MaxRunes)
	}
	if len(name) > MaxBytes {
		return fmt.Errorf("公开名称最多 %d 字节", MaxBytes)
	}
	for _, r := range name {
		if r == utf8.RuneError || unicode.IsControl(r) {
			return errors.New("公开名称不能包含控制字符")
		}
	}
	if strings.TrimSpace(name) != name {
		return errors.New("公开名称首尾不能有空白")
	}
	return nil
}

// Default is the alias used when the user did not type one. It is derived from
// the share identity only, never from the VPN point, the account or the
// computer name.
func Default(shareID string) string {
	tail := shareID
	if len(tail) > 6 {
		tail = tail[:6]
	}
	if tail == "" {
		tail = "------"
	}
	return "Connect Hub 分享 " + tail
}
