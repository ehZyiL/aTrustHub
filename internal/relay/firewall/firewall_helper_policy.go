package firewall

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// FirewallOpDirPrefix is the name prefix of the per-invocation directory the
// desktop creates for one privileged operation.
const FirewallOpDirPrefix = "connect-hub-firewall-"

// ValidateHelperOperation re-checks, inside the elevated helper, what it is
// about to do. The helper must not trust the operation file: a same-user process
// can write one and ask for elevation itself.
//
// Two properties matter, and both are enforced from the helper's own view of the
// world rather than from the request:
//
//   - the rule may only authorize this installation's desktop program, so the
//     helper cannot be used to open a port for somebody else's binary;
//   - the rule may only cover the kind of scope a share produces: one inbound,
//     private-profile TCP port on a private (RFC1918) subnet, never a /0 or a
//     public range.
//
// allowedProgram is resolved by the platform from the helper's own location.
// An empty value is a hard failure: an unknown installation must fail closed.
func ValidateHelperOperation(op FirewallOperation, allowedProgram string) error {
	if err := op.Validate(); err != nil {
		return err
	}
	if op.Op != FirewallOpApply {
		return nil
	}
	if allowedProgram == "" {
		return errors.New("无法确认本程序路径，拒绝执行防火墙操作")
	}
	if !sameProgramPath(op.Rule.ProgramPath, allowedProgram) {
		return errors.New("防火墙规则只能针对本程序，拒绝执行")
	}
	if op.Rule.RemoteIP == "" {
		return errors.New("防火墙规则必须限定在分享网段内")
	}
	_, network, err := net.ParseCIDR(op.Rule.RemoteIP)
	if err != nil {
		return errors.New("防火墙规则的局域网范围无效")
	}
	ip := network.IP.To4()
	if ip == nil || !privateIPv4(ip) {
		return errors.New("防火墙规则的局域网范围必须是私有网段")
	}
	// A /8 is a legitimate corporate LAN, so the ceiling is the private space
	// itself: anything wider would cover addresses outside RFC1918.
	if ones, _ := network.Mask.Size(); ones < 8 {
		return errors.New("防火墙规则的局域网范围过大，拒绝执行")
	}
	return nil
}

// ValidateHelperPaths keeps both files of one invocation together. Because the
// operation file has to exist inside that directory already, and the caller must
// be able to create it, the elevated write can only land somewhere the caller
// could write anyway. That removes the "elevated write to an arbitrary path"
// primitive without needing a per-user temp comparison (which would break
// elevation through another administrator's credentials).
func ValidateHelperPaths(opPath, resultPath string) error {
	if opPath == "" || resultPath == "" {
		return errors.New("防火墙操作缺少文件路径")
	}
	if !filepath.IsAbs(opPath) || !filepath.IsAbs(resultPath) {
		return errors.New("防火墙操作的文件路径必须是绝对路径")
	}
	opDir := filepath.Clean(filepath.Dir(opPath))
	if !strings.EqualFold(opDir, filepath.Clean(filepath.Dir(resultPath))) {
		return errors.New("结果文件必须与操作文件在同一目录")
	}
	if base := filepath.Base(opDir); !strings.HasPrefix(strings.ToLower(base), FirewallOpDirPrefix) {
		return errors.New("防火墙操作目录不是本程序创建的")
	}
	info, err := os.Lstat(opPath)
	if err != nil {
		return errors.New("防火墙操作文件不存在")
	}
	if !info.Mode().IsRegular() {
		return errors.New("防火墙操作文件不是普通文件")
	}
	return nil
}

// sameProgramPath compares two Windows paths the way the file system does:
// case-insensitively and after cleaning.
func sameProgramPath(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	ca, errA := filepath.Abs(a)
	cb, errB := filepath.Abs(b)
	if errA != nil || errB != nil {
		return false
	}
	return strings.EqualFold(filepath.Clean(ca), filepath.Clean(cb))
}
