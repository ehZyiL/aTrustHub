package lanname

import "testing"

// The alias travels inside a DNS-SD TXT value, which is a DNS character-string:
// packing a backslash turns it into an escape (\DDD or \X), so a name containing
// one would arrive at the colleague as a different string. Every boundary runs
// Valid, so refusing it here refuses it on save, on publish and on receive.
func TestValidRefusesABackslash(t *testing.T) {
	for _, name := range []string{`a\065b`, `\\`, `共享\`, `\`} {
		if err := Valid(name); err == nil {
			t.Fatalf("%q 含有反斜杠，应当被拒绝", name)
		}
	}
}

// Everything else a colleague might type is still accepted, so the new rule does
// not narrow the feature beyond the characters that cannot travel unchanged.
func TestValidKeepsAcceptingOrdinaryNames(t *testing.T) {
	for _, name := range []string{"会议室甲", "Connect Hub 分享 AB12CD", "a=b", "100% 网络", "3F-东侧"} {
		if err := Valid(name); err != nil {
			t.Fatalf("%q 被拒绝：%v", name, err)
		}
	}
}

// Default is derived from the share identity alone and must always be a name the
// rules accept, otherwise the fallback would be refused at the publish boundary.
func TestDefaultIsAlwaysValid(t *testing.T) {
	for _, shareID := range []string{"", "A", "AAAAAAAAAAAAAAAAAAAAAA"} {
		name := Default(shareID)
		if err := Valid(name); err != nil {
			t.Fatalf("Default(%q) = %q 不合法：%v", shareID, name, err)
		}
	}
}
