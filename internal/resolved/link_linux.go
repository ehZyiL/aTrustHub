// Package resolved owns a dedicated systemd-resolved DNS link. It never edits
// another interface, /etc/resolv.conf, or the manager's global DNS settings.
package resolved

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Command func(context.Context, string, string, ...string) ([]byte, error)

type Config struct {
	Address string   `json:"address"`
	Domains []string `json:"domains"`
}

func (c Config) Validate() error {
	host, port, err := net.SplitHostPort(c.Address)
	n, e := strconv.Atoi(port)
	if err != nil || e != nil || host != "127.0.0.1" || n < 1024 || n > 65535 {
		return errors.New("DNS 入口必须是本地普通用户端口")
	}
	if len(c.Domains) == 0 || len(c.Domains) > 128 {
		return errors.New("内网 DNS 后缀数量须为 1–128")
	}
	for _, domain := range c.Domains {
		if !validDomain(domain) {
			return errors.New("内网 DNS 后缀无效或范围过大")
		}
	}
	if !sort.StringsAreSorted(c.Domains) {
		return errors.New("DNS 后缀必须排序")
	}
	for i := 1; i < len(c.Domains); i++ {
		if c.Domains[i] == c.Domains[i-1] {
			return errors.New("DNS 后缀重复")
		}
	}
	return nil
}

func validDomain(name string) bool {
	if len(name) > 253 || !strings.Contains(name, ".") || name != strings.ToLower(name) {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	_, err := netip.ParseAddr(name)
	return err != nil
}

// Lease is persisted by the capture transaction before any kernel change. DNS
// credentials never cross this boundary; the DNS protocol itself has no login.
type Lease struct {
	ID      string `json:"id"`
	Address string `json:"linkAddress"`
	Config  Config `json:"config"`
}

func (l Lease) Name() string  { return "echd" + l.ID[:10] }
func (l Lease) owner() string { return "easyconnect-hub-dns:v1:" + l.ID }

// Name and locally administered MAC mark creation atomically. iproute2 does
// not retain ifalias during LinkAdd on every kernel; alias is added afterward.
func (l Lease) mac() string {
	return "02:" + l.ID[10:12] + ":" + l.ID[12:14] + ":" + l.ID[14:16] + ":" + l.ID[16:18] + ":" + l.ID[18:20]
}
func (l Lease) Validate() error {
	b, err := hex.DecodeString(l.ID)
	ip, e := netip.ParseAddr(l.Address)
	if err != nil || len(b) != 16 || l.ID != strings.ToLower(l.ID) || e != nil || !netip.MustParsePrefix("169.254.0.0/16").Contains(ip) {
		return errors.New("invalid DNS lease identity")
	}
	return l.Config.Validate()
}

const managerPath = "/org/freedesktop/resolve1"
const managerInterface = "org.freedesktop.resolve1.Manager"

func bus(ctx context.Context, run Command, args ...string) ([]byte, error) {
	prefix := []string{"--system", "--no-pager", "--allow-interactive-authorization=no", "--timeout=3", "--json=short"}
	return run(ctx, "busctl", "", append(prefix, args...)...)
}
func property(ctx context.Context, run Command, path, iface, name string, v any) error {
	b, err := bus(ctx, run, "get-property", "org.freedesktop.resolve1", path, iface, name)
	if err != nil {
		return err
	}
	var value struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(b, &value); err != nil {
		return err
	}
	return json.Unmarshal(value.Data, v)
}
func call(ctx context.Context, run Command, method, signature string, args ...string) error {
	_, err := bus(ctx, run, append([]string{"call", "org.freedesktop.resolve1", managerPath, managerInterface, method, signature}, args...)...)
	return err
}

func (c Config) Same(other Config) bool {
	return c.Address == other.Address && strings.Join(c.Domains, "\n") == strings.Join(other.Domains, "\n")
}

// Conflicting routing domains are rejected, including a foreign more-specific
// domain. A pre-existing root route (~.) remains the fallback for public names.
func checkDomains(ctx context.Context, run Command, want []string, ownIndex int) error {
	var rows [][]json.RawMessage
	if err := property(ctx, run, managerPath, managerInterface, "Domains", &rows); err != nil {
		return err
	}
	for _, row := range rows {
		if len(row) != 3 {
			return errors.New("invalid resolved domain state")
		}
		var index int
		var name string
		if json.Unmarshal(row[0], &index) != nil || json.Unmarshal(row[1], &name) != nil {
			return errors.New("invalid resolved domain state")
		}
		name = strings.TrimSuffix(strings.ToLower(name), ".")
		if index == ownIndex && ownIndex > 0 || name == "" {
			continue
		}
		for _, domain := range want {
			if name == domain || strings.HasSuffix(name, "."+domain) || strings.HasSuffix(domain, "."+name) {
				return fmt.Errorf("DNS 域名 %s 与已有系统解析规则重叠", domain)
			}
		}
	}
	// Delegate scopes are not exposed in the manager's Domains array. Until
	// their configuration can be compared, decline rather than send parallel DNS.
	b, err := bus(ctx, run, "call", "org.freedesktop.resolve1", managerPath, managerInterface, "ListDelegates")
	if err != nil {
		return errors.New("无法检查 systemd-resolved DNS 委托，需要支持 ListDelegates 的版本")
	}
	var delegates struct {
		Data json.RawMessage `json:"data"`
	}
	if json.Unmarshal(b, &delegates) != nil {
		return errors.New("invalid resolved delegate state")
	}
	var arrays []json.RawMessage
	if json.Unmarshal(delegates.Data, &arrays) != nil || len(arrays) != 1 {
		return errors.New("invalid resolved delegate list")
	}
	var entries []json.RawMessage
	if json.Unmarshal(arrays[0], &entries) != nil || len(entries) > 0 {
		return errors.New("系统已有 DNS 委托，尚未完成共存适配")
	}
	return nil
}

type linkState struct {
	Index   int      `json:"ifindex"`
	Name    string   `json:"ifname"`
	Alias   string   `json:"ifalias"`
	Address string   `json:"address"`
	Flags   []string `json:"flags"`
	Info    struct {
		Kind string `json:"info_kind"`
	} `json:"linkinfo"`
}

func links(ctx context.Context, run Command) ([]linkState, error) {
	b, err := run(ctx, "ip", "", "-j", "-d", "link", "show")
	if err != nil {
		return nil, err
	}
	var out []linkState
	err = json.Unmarshal(b, &out)
	return out, err
}
func findLink(ctx context.Context, run Command, l Lease) (*linkState, error) {
	list, err := links(ctx, run)
	if err != nil {
		return nil, err
	}
	for _, link := range list {
		if link.Name == l.Name() {
			if (link.Alias != "" && link.Alias != l.owner()) || link.Address != l.mac() || link.Info.Kind != "dummy" {
				return nil, errors.New("DNS 接口所有权已变化，拒绝操作")
			}
			return &link, nil
		}
	}
	return nil, nil
}

func Prepare(ctx context.Context, run Command, c Config) (*Lease, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	var mode string
	if err := property(ctx, run, managerPath, managerInterface, "ResolvConfMode", &mode); err != nil {
		return nil, errors.New("systemd-resolved 不可用，无法安装分域 DNS")
	}
	if mode != "stub" {
		return nil, errors.New("当前系统未使用 systemd-resolved stub，无法保证软件 DNS 生效")
	}
	if err := checkDomains(ctx, run, c.Domains, 0); err != nil {
		return nil, err
	}
	b, err := run(ctx, "ip", "", "-j", "-4", "route", "show", "table", "all")
	if err != nil {
		return nil, err
	}
	var routes []struct {
		Dst  string `json:"dst"`
		Type string `json:"type"`
	}
	if err := json.Unmarshal(b, &routes); err != nil {
		return nil, err
	}
	var used []netip.Prefix
	linkLocal := netip.MustParsePrefix("169.254.0.0/16")
	for _, r := range routes {
		if r.Dst == "" || r.Dst == "default" || r.Dst == "0.0.0.0/0" {
			continue
		}
		p, err := netip.ParsePrefix(r.Dst)
		if err != nil {
			if addr, e := netip.ParseAddr(r.Dst); e == nil {
				p = netip.PrefixFrom(addr, 32)
			} else {
				continue
			}
		}
		// A broad unicast route is an existing transport path (for example a
		// TUN's 168.0.0.0/6), not an allocation of every link-local address.
		// The owned /32 is only a DNS-link anchor. Still reserve specific
		// networks/host routes and local/blackhole/prohibit routing policy.
		if p.Overlaps(linkLocal) && (p.Bits() >= linkLocal.Bits() || (r.Type != "" && r.Type != "unicast")) {
			used = append(used, p)
		}
	}
	list, err := links(ctx, run)
	if err != nil {
		return nil, err
	}
	for range 256 {
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			return nil, err
		}
		ip := netip.AddrFrom4([4]byte{169, 254, 1 + id[0]%253, 1 + id[1]%253})
		l := &Lease{ID: hex.EncodeToString(id[:]), Address: ip.String(), Config: c}
		conflict := false
		for _, p := range used {
			if p.Contains(ip) {
				conflict = true
				break
			}
		}
		for _, link := range list {
			if link.Name == l.Name() {
				conflict = true
				break
			}
		}
		if !conflict {
			return l, nil
		}
	}
	return nil, errors.New("没有可用的链路本地地址来创建 DNS 接口")
}

func Install(ctx context.Context, run Command, l Lease) error {
	if err := l.Validate(); err != nil {
		return err
	}
	if err := checkDomains(ctx, run, l.Config.Domains, 0); err != nil {
		return err
	}
	if _, err := run(ctx, "ip", "", "link", "add", "name", l.Name(), "address", l.mac(), "type", "dummy"); err != nil {
		return err
	}
	if _, err := run(ctx, "ip", "", "link", "set", "dev", l.Name(), "alias", l.owner()); err != nil {
		return err
	}
	if _, err := run(ctx, "ip", "", "-4", "addr", "add", l.Address+"/32", "dev", l.Name(), "noprefixroute"); err != nil {
		return err
	}
	if _, err := run(ctx, "ip", "", "link", "set", "dev", l.Name(), "up"); err != nil {
		return err
	}
	link, err := findLink(ctx, run, l)
	if err != nil {
		return err
	}
	if link == nil {
		return errors.New("DNS 接口未就绪")
	}
	index := strconv.Itoa(link.Index)
	// Netlink notification reaches resolved asynchronously.
	var readyErr error
	for range 25 {
		readyErr = call(ctx, run, "SetLinkDefaultRoute", "ib", index, "false")
		if readyErr == nil {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
	if readyErr != nil {
		return readyErr
	}
	for _, method := range []string{"SetLinkLLMNR", "SetLinkMulticastDNS", "SetLinkDNSOverTLS", "SetLinkDNSSEC"} {
		if err := call(ctx, run, method, "is", index, "no"); err != nil {
			return err
		}
	}
	_, port, _ := net.SplitHostPort(l.Config.Address)
	if err := call(ctx, run, "SetLinkDNSEx", "ia(iayqs)", index, "1", "2", "4", "127", "0", "0", "1", port, ""); err != nil {
		return err
	}
	args := []string{index, strconv.Itoa(len(l.Config.Domains))}
	for _, d := range l.Config.Domains {
		args = append(args, d, "true")
	}
	if err := call(ctx, run, "SetLinkDomains", "ia(sb)", args...); err != nil {
		return err
	}
	return Verify(ctx, run, l)
}

func Verify(ctx context.Context, run Command, l Lease) error {
	if err := l.Validate(); err != nil {
		return err
	}
	var mode string
	if err := property(ctx, run, managerPath, managerInterface, "ResolvConfMode", &mode); err != nil {
		return err
	}
	if mode != "stub" {
		return errors.New("系统已切换解析入口，内网 DNS 接管已失效")
	}
	link, err := findLink(ctx, run, l)
	if err != nil {
		return err
	}
	if link == nil {
		return errors.New("DNS 接口已消失")
	}
	if link.Alias != l.owner() {
		return errors.New("DNS 接口所有权标记丢失")
	}
	up := false
	for _, f := range link.Flags {
		if f == "UP" {
			up = true
		}
	}
	if !up {
		return errors.New("DNS 接口已停止")
	}
	b, err := bus(ctx, run, "call", "org.freedesktop.resolve1", managerPath, managerInterface, "GetLink", "i", strconv.Itoa(link.Index))
	if err != nil {
		return err
	}
	var object struct {
		Data []string `json:"data"`
	}
	if json.Unmarshal(b, &object) != nil || len(object.Data) != 1 || !strings.HasPrefix(object.Data[0], managerPath+"/link/") {
		return errors.New("invalid resolved link object")
	}
	path := object.Data[0]
	const iface = "org.freedesktop.resolve1.Link"
	// This link returns filtered capture answers over a local plain socket.
	// DNSSEC and DoT settings apply only to this owned link, not public DNS.
	for _, name := range []string{"DNSSEC", "DNSOverTLS", "LLMNR", "MulticastDNS"} {
		var value string
		if err := property(ctx, run, path, iface, name, &value); err != nil {
			return err
		}
		if value != "no" {
			return errors.New("DNS 接口的解析策略已变化")
		}
	}
	var defaultRoute bool
	if err := property(ctx, run, path, iface, "DefaultRoute", &defaultRoute); err != nil {
		return err
	}
	if defaultRoute {
		return errors.New("DNS 接口被改为默认解析路径")
	}
	var domains [][]json.RawMessage
	if err := property(ctx, run, path, iface, "Domains", &domains); err != nil {
		return err
	}
	var names []string
	for _, d := range domains {
		var name string
		var routing bool
		if len(d) != 2 || json.Unmarshal(d[0], &name) != nil || json.Unmarshal(d[1], &routing) != nil || !routing {
			return errors.New("DNS 域策略被修改")
		}
		names = append(names, name)
	}
	sort.Strings(names)
	if strings.Join(names, "\n") != strings.Join(l.Config.Domains, "\n") {
		return errors.New("DNS 域策略已变化")
	}
	var servers [][]json.RawMessage
	if err := property(ctx, run, path, iface, "DNSEx", &servers); err != nil {
		return err
	}
	if len(servers) != 1 || len(servers[0]) != 4 {
		return errors.New("DNS 服务器配置已变化")
	}
	var family, port int
	var address []int
	var name string
	row := servers[0]
	if json.Unmarshal(row[0], &family) != nil || json.Unmarshal(row[1], &address) != nil || json.Unmarshal(row[2], &port) != nil || json.Unmarshal(row[3], &name) != nil {
		return errors.New("invalid DNS server state")
	}
	if family != 2 || fmt.Sprint(address) != "[127 0 0 1]" || name != "" || net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) != l.Config.Address {
		return errors.New("DNS 服务器配置被替换")
	}
	return checkDomains(ctx, run, l.Config.Domains, link.Index)
}

func Remove(ctx context.Context, run Command, l Lease) error {
	if err := l.Validate(); err != nil {
		return err
	}
	link, err := findLink(ctx, run, l)
	if err != nil {
		return err
	}
	if link == nil {
		return nil
	}
	_, err = run(ctx, "ip", "", "link", "delete", "dev", l.Name())
	return err
}
