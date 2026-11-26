package contract

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func validShare() ShareCode {
	return ShareCode{
		Version:     1,
		Host:        "192.168.1.50",
		Port:        23456,
		ShareID:     base64.RawURLEncoding.EncodeToString(bytesN(16, 7)),
		Token:       base64.RawURLEncoding.EncodeToString(bytesN(32, 11)),
		Fingerprint: strings.Repeat("ab", 32),
		Name:        "现场主机",
	}
}

func bytesN(n int, seed byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = seed + byte(i)
	}
	return b
}

func TestShareCodeRoundTrip(t *testing.T) {
	original := validShare()
	text := original.String()
	if !strings.HasPrefix(text, "connect-hub://relay/v1#") {
		t.Fatalf("unexpected prefix: %s", text)
	}
	parsed, err := ParseShareCode(text)
	if err != nil {
		t.Fatalf("ParseShareCode: %v", err)
	}
	if parsed != original {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", parsed, original)
	}
	if parsed.Address() != "192.168.1.50:23456" {
		t.Fatalf("address = %q", parsed.Address())
	}
}

// payload builds a share code with an arbitrary JSON object body, so each
// rejection case can target exactly one rule.
func payload(t *testing.T, mutate func(map[string]any) (map[string]any, bool)) string {
	t.Helper()
	obj := map[string]any{
		"v":     1,
		"h":     "192.168.1.50",
		"p":     23456,
		"sid":   base64.RawURLEncoding.EncodeToString(bytesN(16, 7)),
		"token": base64.RawURLEncoding.EncodeToString(bytesN(32, 11)),
		"fp":    strings.Repeat("ab", 32),
	}
	if mutate != nil {
		next, ok := mutate(obj)
		if !ok {
			return ""
		}
		obj = next
	}
	b, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	return "connect-hub://relay/v1#" + base64.RawURLEncoding.EncodeToString(b)
}

func rawPayload(t *testing.T, body string) string {
	return "connect-hub://relay/v1#" + base64.RawURLEncoding.EncodeToString([]byte(body))
}

func TestShareCodeRejectsMalformed(t *testing.T) {
	validFP := strings.Repeat("ab", 32)
	validSID := base64.RawURLEncoding.EncodeToString(bytesN(16, 7))
	validToken := base64.RawURLEncoding.EncodeToString(bytesN(32, 11))
	cases := []struct {
		name string
		text string
	}{
		{"empty", ""},
		{"not a share code", "hello 世界"},
		{"old scheme", "hub://relay?token=abc"},
		{"wrong authority", "connect-hub://share/v1#" + base64.RawURLEncoding.EncodeToString([]byte("{}"))},
		{"wrong path", "connect-hub://relay/v2#" + base64.RawURLEncoding.EncodeToString([]byte("{}"))},
		{"userinfo", "connect-hub://user@relay/v1#" + base64.RawURLEncoding.EncodeToString([]byte("{}"))},
		{"query", "connect-hub://relay/v1?x=1#" + base64.RawURLEncoding.EncodeToString([]byte("{}"))},
		{"no fragment", "connect-hub://relay/v1"},
		{"empty fragment", "connect-hub://relay/v1#"},
		{"padded base64", "connect-hub://relay/v1#" + base64.RawURLEncoding.EncodeToString([]byte("{}")) + "=="},
		{"invalid base64 char", "connect-hub://relay/v1#abcd*efg"},
		{"payload not object", rawPayload(t, `"nope"`)},
		{"trailing json", rawPayload(t, `{"v":1}{"v":1}`)},
		{"trailing garbage", rawPayload(t, `{"v":1} x`)},
		{"unknown field", payload(t, func(m map[string]any) (map[string]any, bool) { m["extra"] = 1; return m, true })},
		{"duplicate field", rawPayload(t, `{"v":1,"v":1,"h":"192.168.1.50","p":1,"sid":"`+validSID+`","token":"`+validToken+`","fp":"`+validFP+`"}`)},
		{"missing token", payload(t, func(m map[string]any) (map[string]any, bool) { delete(m, "token"); return m, true })},
		{"version 2", payload(t, func(m map[string]any) (map[string]any, bool) { m["v"] = 2; return m, true })},
		{"version string", payload(t, func(m map[string]any) (map[string]any, bool) { m["v"] = "1"; return m, true })},
		{"port zero", payload(t, func(m map[string]any) (map[string]any, bool) { m["p"] = 0; return m, true })},
		{"port overflow", payload(t, func(m map[string]any) (map[string]any, bool) { m["p"] = 70000; return m, true })},
		{"port float", payload(t, func(m map[string]any) (map[string]any, bool) { m["p"] = 1.5; return m, true })},
		{"port exponent", rawPayload(t, `{"v":1,"h":"192.168.1.50","p":1e3,"sid":"`+validSID+`","token":"`+validToken+`","fp":"`+validFP+`"}`)},
		{"port with port suffix", payload(t, func(m map[string]any) (map[string]any, bool) { m["h"] = "192.168.1.50:22"; return m, true })},
		{"public host", payload(t, func(m map[string]any) (map[string]any, bool) { m["h"] = "8.8.8.8"; return m, true })},
		{"loopback host", payload(t, func(m map[string]any) (map[string]any, bool) { m["h"] = "127.0.0.1"; return m, true })},
		{"unspecified host", payload(t, func(m map[string]any) (map[string]any, bool) { m["h"] = "0.0.0.0"; return m, true })},
		{"multicast host", payload(t, func(m map[string]any) (map[string]any, bool) { m["h"] = "224.0.0.1"; return m, true })},
		{"hostname instead of ip", payload(t, func(m map[string]any) (map[string]any, bool) { m["h"] = "nas.local"; return m, true })},
		{"ipv6 host", payload(t, func(m map[string]any) (map[string]any, bool) { m["h"] = "fd00::1"; return m, true })},
		{"short sid", payload(t, func(m map[string]any) (map[string]any, bool) { m["sid"] = validSID[:10]; return m, true })},
		{"padded sid", payload(t, func(m map[string]any) (map[string]any, bool) { m["sid"] = validSID + "="; return m, true })},
		{"short token", payload(t, func(m map[string]any) (map[string]any, bool) { m["token"] = validToken[:20]; return m, true })},
		{"uppercase fp", payload(t, func(m map[string]any) (map[string]any, bool) { m["fp"] = strings.ToUpper(validFP); return m, true })},
		{"short fp", payload(t, func(m map[string]any) (map[string]any, bool) { m["fp"] = validFP[:32]; return m, true })},
		{"non-hex fp", payload(t, func(m map[string]any) (map[string]any, bool) { m["fp"] = strings.Repeat("zz", 32); return m, true })},
		{"control char name", payload(t, func(m map[string]any) (map[string]any, bool) { m["name"] = "bad\x00name"; return m, true })},
		{"name too long", payload(t, func(m map[string]any) (map[string]any, bool) { m["name"] = strings.Repeat("名", 81); return m, true })},
		{"oversized text", "connect-hub://relay/v1#" + strings.Repeat("A", MaxShareCodeBytes)},
		{"oversized json", rawPayload(t, `{"v":1,"h":"192.168.1.50","pad":"`+strings.Repeat("x", MaxShareCodeJSON)+`"}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseShareCode(tc.text); err == nil {
				t.Fatalf("expected rejection for %q", tc.name)
			}
		})
	}
}

func TestShareCodeNotShareCodeIsDistinguishable(t *testing.T) {
	_, err := ParseShareCode("随便一段剪贴板文字")
	if !errors.Is(err, ErrNotShareCode) {
		t.Fatalf("want ErrNotShareCode, got %v", err)
	}
	// A structurally similar but invalid code must not be mistaken for
	// unrelated clipboard text.
	_, err = ParseShareCode("connect-hub://relay/v1#!!!")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !errors.Is(err, ErrNotShareCode) {
		t.Fatalf("invalid share code should still be reported as share-code text: %v", err)
	}
}

func TestShareCodeNameOptional(t *testing.T) {
	code := validShare()
	code.Name = ""
	parsed, err := ParseShareCode(code.String())
	if err != nil {
		t.Fatalf("nameless code rejected: %v", err)
	}
	if parsed.DisplayName() != "192.168.1.50:23456" {
		t.Fatalf("display name = %q", parsed.DisplayName())
	}
	if strings.Contains(code.String(), `"name"`) {
		t.Fatal("empty name should be omitted from the payload")
	}
}

func TestShareCodeFuzzParseDoesNotPanic(t *testing.T) {
	base := validShare().String()
	for i := 0; i < 2000; i++ {
		b := []byte(base)
		if len(b) > 0 {
			b[i%len(b)] = byte(i)
		}
		_, _ = ParseShareCode(string(b))
	}
}
