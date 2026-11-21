package wincapture

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"strings"

	"github.com/ehZyiL/connect-hub/internal/dnsmapping"
	"github.com/ehZyiL/connect-hub/internal/netpolicy"
	"github.com/ehZyiL/connect-hub/internal/workeripc"
)

const ProtocolVersion = 7
const maxFrame = 256 << 10

type Config struct {
	GatewayID       string            `json:"gatewayID"`
	Generation      int               `json:"generation"`
	ResourceVersion string            `json:"resourceVersion"`
	Scope           string            `json:"scope"`
	Gateway         string            `json:"gateway"`
	Networks        []netpolicy.Range `json:"networks,omitempty"`
	DNSAddress      string            `json:"dnsAddress,omitempty"`
	SharedDNS       bool              `json:"sharedDNS,omitempty"`
	Domains         []string          `json:"domains,omitempty"`
	ReservedPools   []string          `json:"reservedPools,omitempty"`
	AliasNetworks   []netpolicy.Range `json:"aliasNetworks,omitempty"`
}

type Upstream struct {
	Address  string `json:"address"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func (u Upstream) validate() error {
	a, err := netip.ParseAddrPort(u.Address)
	if err != nil || a.Addr() != netip.MustParseAddr("127.0.0.1") || a.Port() < 1024 ||
		len(u.Username) < 1 || len(u.Username) > 128 || len(u.Password) < 32 || len(u.Password) > 128 {
		return errors.New("网络助手需要带会话认证的本机代理端口")
	}
	return nil
}

func (c Config) validate() error {
	if c.GatewayID == "" || len(c.GatewayID) > 256 || c.Generation < 0 || c.ResourceVersion == "" || len(c.ResourceVersion) > 256 || c.Scope != "application" {
		return errors.New("网络助手缺少有效的网关代次、资源版本或接管作用域")
	}
	if err := dnsmapping.ValidateReservations(c.ReservedPools); err != nil {
		return err
	}
	if len(c.AliasNetworks) > 4096 {
		return errors.New("映射冲突检查资源过多")
	}
	for _, r := range c.AliasNetworks {
		lo, e1 := netip.ParseAddr(r.Min)
		hi, e2 := netip.ParseAddr(r.Max)
		if e1 != nil || e2 != nil || lo.BitLen() != hi.BitLen() || lo.Compare(hi) > 0 {
			return errors.New("映射冲突检查范围无效")
		}
	}
	if c.Gateway == "" || len(c.Gateway) > 253 || strings.ContainsAny(c.Gateway, " /\\\r\n\t\x00@?#") {
		return errors.New("缺少或无效的 VPN 网关主机名")
	}
	if _, err := ResourcePrefixes(c.Networks); err != nil {
		return err
	}
	if len(c.Domains) > 128 {
		return errors.New("内网 DNS 后缀过多")
	}
	for _, domain := range c.Domains {
		if len(domain) > 253 || !strings.Contains(domain, ".") || strings.Trim(domain, ".") != domain {
			return errors.New("无效的内网 DNS 后缀")
		}
		for _, ch := range domain {
			if ch != '.' && ch != '-' && !(ch >= '0' && ch <= '9') && !(ch >= 'a' && ch <= 'z') {
				return errors.New("无效的内网 DNS 后缀")
			}
		}
		for _, label := range strings.Split(domain, ".") {
			if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
				return errors.New("无效的内网 DNS 后缀")
			}
		}
	}
	if len(c.Domains) != 0 {
		a, err := netip.ParseAddrPort(c.DNSAddress)
		if err != nil || a.Addr() != netip.MustParseAddr("127.0.0.1") || a.Port() < 1024 {
			return errors.New("DNS 入口必须为本机会话端口")
		}
	} else if c.DNSAddress != "" {
		return errors.New("DNS 入口缺少域名范围")
	}
	return nil
}

type attach struct {
	ID       string   `json:"id"`
	Job      uint64   `json:"job"`
	Upstream Upstream `json:"upstream"`
}

type frame struct {
	Version  int                  `json:"version"`
	Type     string               `json:"type"`
	Session  string               `json:"session,omitempty"`
	Config   *Config              `json:"config,omitempty"`
	Attach   *attach              `json:"attach,omitempty"`
	ID       string               `json:"id,omitempty"`
	Prefix   string               `json:"prefix,omitempty"`
	Aliases  []workeripc.DNSAlias `json:"aliases,omitempty"`
	Upstream *Upstream            `json:"upstream,omitempty"`
	Error    string               `json:"error,omitempty"`
}

func readFrame(r *bufio.Reader, v *frame) error {
	data, err := r.ReadSlice('\n')
	if err != nil {
		return err
	}
	if len(data) > maxFrame {
		return errors.New("网络助手消息过长")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err = d.Decode(v); err != nil {
		return errors.New("网络助手消息无效")
	}
	if d.Decode(new(any)) != io.EOF || v.Version != ProtocolVersion {
		return errors.New("网络助手版本不兼容")
	}
	return nil
}

func writeFrame(w io.Writer, v frame) error {
	v.Version = ProtocolVersion
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(data)+1 > maxFrame {
		return errors.New("网络助手消息过长")
	}
	n, err := w.Write(append(data, '\n'))
	if err == nil && n != len(data)+1 {
		return io.ErrShortWrite
	}
	return err
}
