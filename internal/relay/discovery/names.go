package discovery

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/ehzyil/connect-hub/internal/lanname"
	"github.com/ehzyil/connect-hub/internal/model"
)

// instancePrefix marks our instances inside the shared service type, so a
// browser can recognise them without parsing TXT.
const instancePrefix = "CH-"

// InstanceName is the DNS-SD instance name of a share. The share ID is the
// instance identity; the human-readable alias lives in TXT and can change
// without touching the instance.
func InstanceName(shareID string) string {
	return instancePrefix + shareID + "." + ServiceType
}

// HostLabel is the SRV target of a share. It is lowercase-only and derived from
// the share ID, so the published address records never expose a system host
// name.
func HostLabel(shareID string) string {
	return "ch-" + strings.ToLower(shareID) + ".local."
}

// IsInstance reports whether a DNS name belongs to this feature's service type.
// DNS names are case-insensitive, so the comparison is too.
func IsInstance(name string) bool {
	return strings.HasSuffix(strings.ToLower(name), "."+strings.ToLower(ServiceType)) ||
		strings.EqualFold(name, ServiceType)
}

// shareIDFromLabel extracts the share ID part of an instance label. It only
// works for the exact form we publish; anything else is rejected.
func shareIDFromLabel(label string) (string, bool) {
	if len(label) <= len(instancePrefix) {
		return "", false
	}
	if !strings.EqualFold(label[:len(instancePrefix)], instancePrefix) {
		return "", false
	}
	return label[len(instancePrefix):], true
}

// txtFields is the parsed content of one TXT record. Unknown keys are ignored
// but counted, so the field budget still bounds a hostile record.
type txtFields struct {
	Pairing         bool
	DraftVersion    int
	ProtocolVersion int
	ShareID         string
	Name            string
	Unknown         int
}

// BuildTXT serialises the legacy fields and an optional pairing capability.
func BuildTXT(a Announcement) []string {
	fields := []string{
		"dv=" + strconv.Itoa(DraftVersion),
		"pv=" + strconv.Itoa(a.ProtocolVersion),
		"sid=" + a.ShareID,
		"name=" + a.Name,
	}
	if a.Pairing {
		fields = append(fields, "pair=opaque-ed25519-v2")
	}
	return fields
}

// ParseTXT validates a received TXT record. Required keys are dv, pv and sid;
// name is optional. A record that is too large, has duplicate or over-long
// fields, or carries an unusable value is refused as a whole: a half-understood
// announcement is not a candidate.
func ParseTXT(parts []string) (txtFields, error) {
	var out txtFields
	total := 0
	for _, part := range parts {
		total += len(part) + 1
	}
	if total > MaxTXTBytes {
		return out, errors.New("TXT 记录过大")
	}
	// RFC 6763 section 6.4: a value longer than one character-string is split
	// across several, which are concatenated. A chunk without "=" continues the
	// previous value, so a long UTF-8 name survives the 255 byte limit.
	joined := make([]string, 0, len(parts))
	for _, part := range parts {
		if !strings.Contains(part, "=") && len(joined) > 0 {
			joined[len(joined)-1] += part
			continue
		}
		joined = append(joined, part)
	}
	if len(joined) > MaxTXTFields {
		return out, errors.New("TXT 字段过多")
	}
	seen := make(map[string]bool, len(joined))
	for _, part := range joined {
		part = unescapeTXT(part)
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			// A key without a value is legal DNS-SD, but none of our keys are
			// boolean, so it cannot be one of them.
			out.Unknown++
			continue
		}
		if seen[key] {
			return out, fmt.Errorf("TXT 键 %q 重复", key)
		}
		seen[key] = true
		switch key {
		case "pair":
			out.Pairing = value == "opaque-ed25519-v2"
		case "dv":
			v, err := strconv.Atoi(value)
			if err != nil {
				return out, errors.New("发现版本不合法")
			}
			out.DraftVersion = v
		case "pv":
			v, err := strconv.Atoi(value)
			if err != nil {
				return out, errors.New("分享协议版本不合法")
			}
			out.ProtocolVersion = v
		case "sid":
			if !model.ValidShareID(value) {
				return out, errors.New("分享标识不合法")
			}
			out.ShareID = value
		case "name":
			if err := lanname.Valid(value); err != nil {
				return out, err
			}
			out.Name = value
		default:
			out.Unknown++
		}
	}
	if out.DraftVersion == 0 || out.ProtocolVersion == 0 || out.ShareID == "" {
		return out, errors.New("TXT 缺少必填字段")
	}
	return out, nil
}

// unescapeTXT reverses the escaping multicast DNS applies to a character-string:
// "\DDD" is a byte written in decimal, and "\X" is the literal X. Without this
// every non-ASCII name would arrive as backslash sequences and fail validation.
func unescapeTXT(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			out = append(out, s[i])
			continue
		}
		if i+3 < len(s) && digit(s[i+1]) && digit(s[i+2]) && digit(s[i+3]) {
			v := int(s[i+1]-'0')*100 + int(s[i+2]-'0')*10 + int(s[i+3]-'0')
			if v <= 255 {
				out = append(out, byte(v))
				i += 3
				continue
			}
		}
		if i+1 < len(s) {
			out = append(out, s[i+1])
			i++
		}
	}
	return string(out)
}

func digit(c byte) bool { return c >= '0' && c <= '9' }
