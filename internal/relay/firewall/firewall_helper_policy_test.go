package firewall

import (
	"os"
	"path/filepath"
	"testing"
)

const testHelperProgram = `C:\Program Files\Connect Hub\connect-hub.exe`

func applyOp(rule FirewallRule) FirewallOperation {
	return FirewallOperation{
		OperationID: "op-1",
		Op:          FirewallOpApply,
		Rule:        rule,
	}
}

func helperRule() FirewallRule {
	return FirewallRule{
		ID:          FirewallRulePrefix + "share-23456",
		Name:        "Connect Hub 局域网分享",
		ProgramPath: testHelperProgram,
		Port:        23456,
		Profile:     "private",
		RemoteIP:    "192.168.31.0/24",
	}
}

// S1: the helper must only authorize this installation's own program, so a
// same-user process cannot use an approved UAC prompt to open a port for
// something else.
func TestHelperOnlyAuthorizesThisProgram(t *testing.T) {
	ok := helperRule()
	if err := ValidateHelperOperation(applyOp(ok), testHelperProgram); err != nil {
		t.Fatalf("本程序自己的规则被拒绝：%v", err)
	}
	// Case and separators are not a way around the comparison.
	upper := ok
	upper.ProgramPath = `c:\program files\connect hub\CONNECT-HUB.EXE`
	if err := ValidateHelperOperation(applyOp(upper), testHelperProgram); err != nil {
		t.Fatalf("同一路径的大小写差异被拒绝：%v", err)
	}
	for _, foreign := range []string{
		`C:\Users\me\AppData\Local\Temp\evil.exe`,
		`C:\Program Files\Connect Hub\connect-hub-capture.exe`,
		`\\server\share\connect-hub.exe`,
	} {
		rule := ok
		rule.ProgramPath = foreign
		if err := ValidateHelperOperation(applyOp(rule), testHelperProgram); err == nil {
			t.Fatalf("为其它程序创建规则没有被拒绝：%s", foreign)
		}
	}
	// No installation path means no way to prove the target: fail closed.
	if err := ValidateHelperOperation(applyOp(ok), ""); err == nil {
		t.Fatal("未知安装路径时应当拒绝")
	}
}

// S1: the rule shape is narrowed to what a share actually produces.
func TestHelperNarrowsTheRuleShape(t *testing.T) {
	base := helperRule()
	for _, tc := range []struct {
		name   string
		mutate func(*FirewallRule)
	}{
		{"公网网段", func(r *FirewallRule) { r.RemoteIP = "8.8.8.0/24" }},
		{"任意地址", func(r *FirewallRule) { r.RemoteIP = "0.0.0.0/0" }},
		{"比私有空间还大", func(r *FirewallRule) { r.RemoteIP = "10.0.0.0/7" }},
		{"没有网段", func(r *FirewallRule) { r.RemoteIP = "" }},
		{"坏网段", func(r *FirewallRule) { r.RemoteIP = "not-a-cidr" }},
		{"公网配置文件", func(r *FirewallRule) { r.Profile = "public" }},
		{"端口为 0", func(r *FirewallRule) { r.Port = 0 }},
		{"外部规则 ID", func(r *FirewallRule) { r.ID = "SomeoneElsesRule" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := base
			tc.mutate(&rule)
			if err := ValidateHelperOperation(applyOp(rule), testHelperProgram); err == nil {
				t.Fatal("应当拒绝")
			}
		})
	}
	// A /8 LAN and a single address are both shapes a real share produces.
	for _, remote := range []string{"10.0.0.0/8", "192.168.31.61/32"} {
		rule := base
		rule.RemoteIP = remote
		if err := ValidateHelperOperation(applyOp(rule), testHelperProgram); err != nil {
			t.Fatalf("合法网段被拒绝 %s：%v", remote, err)
		}
	}
	// Delete and query only name a rule this app created.
	del := FirewallOperation{OperationID: "op-2", Op: FirewallOpDelete, RuleID: FirewallRulePrefix + "share-1"}
	if err := ValidateHelperOperation(del, testHelperProgram); err != nil {
		t.Fatalf("删除本程序规则被拒绝：%v", err)
	}
	del.RuleID = "OtherRule"
	if err := ValidateHelperOperation(del, testHelperProgram); err == nil {
		t.Fatal("删除别人的规则没有被拒绝")
	}
}

// S1: an elevated helper must not become a write-anywhere primitive. Both files
// belong to the same invocation directory that the caller could already write.
func TestHelperPathsStayInOneInvocationDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), FirewallOpDirPrefix+"abc123")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	opPath := filepath.Join(dir, "op.json")
	if err := os.WriteFile(opPath, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	resultPath := filepath.Join(dir, "result.json")
	if err := ValidateHelperPaths(opPath, resultPath); err != nil {
		t.Fatalf("合法路径被拒绝：%v", err)
	}

	other := filepath.Join(t.TempDir(), FirewallOpDirPrefix+"zzz")
	if err := os.MkdirAll(other, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "op.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		op     string
		result string
	}{
		{"结果文件跑到别的目录", opPath, filepath.Join(other, "result.json")},
		{"相对路径", "op.json", "result.json"},
		{"空路径", "", resultPath},
		{"操作文件不存在", filepath.Join(dir, "missing.json"), filepath.Join(dir, "result.json")},
		{"目录前缀不符", filepath.Join(filepath.Dir(dir), "elsewhere", "op.json"),
			filepath.Join(filepath.Dir(dir), "elsewhere", "result.json")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateHelperPaths(tc.op, tc.result); err == nil {
				t.Fatal("应当拒绝")
			}
		})
	}

	// A symlink cannot be used to smuggle the operation file in from elsewhere.
	outside := filepath.Join(t.TempDir(), "op.json")
	if err := os.WriteFile(outside, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("无法创建符号链接：%v", err)
	}
	if err := ValidateHelperPaths(link, resultPath); err == nil {
		t.Fatal("符号链接没有被拒绝")
	}
}
