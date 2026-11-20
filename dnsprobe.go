package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/miekg/dns"
	"golang.org/x/net/idna"
)

type dnsProbeDraft struct {
	open, running                           bool
	capture                                 bool
	automatic                               bool
	port                                    string
	id, name, domain, kind, result, summary string
	cancel                                  context.CancelFunc
	replies                                 <-chan string
}

func (a *app) openDNSProbe(id, name string) {
	if a.dnsProbe.cancel != nil {
		a.dnsProbe.cancel()
	}
	d := dnsProbeDraft{open: true, id: id, name: name, kind: "A", port: "443", summary: "核心尚未提供 DNS 资源信息"}
	if resources := a.mgr.DNSResources(id); resources != nil {
		server := resources.DNSServer
		if server == "" {
			server = "未下发，可在接入点高级设置补充"
		}
		d.summary = fmt.Sprintf("VPN DNS：%s\n资源：%d 条 IP 规则、%d 条域名规则、%d 条静态解析", server, len(resources.IPRules), len(resources.DomainRules), len(resources.StaticDNS))
	}
	a.dnsProbe = d
}

func dnsProbeQuestion(name, kind string) ([]byte, error) {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "" || net.ParseIP(name) != nil || strings.ContainsAny(name, "/\\:@* ") {
		return nil, errors.New("请填写内网域名，例如 db.corp.example；无需协议或端口")
	}
	ascii, err := idna.Lookup.ToASCII(name)
	if err != nil {
		return nil, errors.New("域名格式无效")
	}
	if _, ok := dns.IsDomainName(dns.Fqdn(ascii)); !ok || len(ascii) > 253 {
		return nil, errors.New("域名格式无效")
	}
	typ, ok := dns.StringToType[kind]
	if !ok {
		return nil, errors.New("请选择有效的 DNS 类型")
	}
	return new(dns.Msg).SetQuestion(dns.Fqdn(ascii), typ).Pack()
}

func dnsProbeResult(packet []byte, err error, capture bool) string {
	if err != nil {
		return "查询失败：" + err.Error()
	}
	m := new(dns.Msg)
	if m.Unpack(packet) != nil {
		return "查询失败：无效的 DNS 应答"
	}
	lines := []string{"结果：" + dns.RcodeToString[m.Rcode]}
	if capture {
		lines[0] = "旧版 IP 授权兼容检查（不代表当前接管链路）：" + dns.RcodeToString[m.Rcode]
	}
	switch m.Rcode {
	case dns.RcodeRefused:
		lines = append(lines, "该域名不在已知内网范围；可在接入点高级设置补充内网后缀。")
	case dns.RcodeServerFailure:
		lines = append(lines, "VPN DNS 未配置、无法访问或未返回有效应答。")
		if capture {
			lines = append(lines, "也可能是地址只有域名授权、缺少 IP 授权，或别名指向未配置的内网后缀。可取消勾选后比较原始解析。")
		}
	case dns.RcodeNameError:
		lines = append(lines, "VPN DNS 报告此域名不存在。")
	case dns.RcodeSuccess:
		if len(m.Answer) == 0 {
			lines = append(lines, "名称可查询，但没有该类型记录。")
			if capture && len(m.Question) > 0 && m.Question[0].Qtype == dns.TypeAAAA {
				lines = append(lines, "软件接管目前不支持内网 IPv6，因此不返回 AAAA 地址。")
			}
		}
	}
	for _, rr := range m.Answer {
		line := rr.String()
		if len(line) > 500 {
			line = line[:500] + "…"
		}
		lines = append(lines, line)
		if len(lines) >= 20 {
			lines = append(lines, "仅显示前 20 行。")
			break
		}
	}
	return strings.Join(lines, "\n")
}

func (a *app) startDNSProbe() {
	d := &a.dnsProbe
	packet, err := dnsProbeQuestion(d.domain, d.kind)
	if err != nil {
		d.result = err.Error()
		return
	}
	if d.cancel != nil {
		d.cancel()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	replies := make(chan string, 1)
	d.cancel, d.replies, d.running, d.result = cancel, replies, true, ""
	id := d.id
	capture := d.capture
	automatic := d.automatic
	go func() {
		defer cancel()
		var answer []byte
		var err error
		if automatic {
			answer, err = a.mgr.ExchangeResourceDNS(ctx, packet)
		} else if capture {
			answer, err = a.mgr.ExchangeCaptureDNS(ctx, id, packet)
		} else {
			answer, err = a.mgr.ExchangeDNS(ctx, id, packet)
		}
		replies <- dnsProbeResult(answer, err, capture && !automatic)
		a.invalidate()
	}()
}

func (a *app) dnsProbeView(c *ui.Context) {
	d := &a.dnsProbe
	if !d.open {
		return
	}
	if d.running {
		select {
		case d.result = <-d.replies:
			d.running = false
		default:
		}
	}
	ui.Modal(c, &d.open, func() {
		ui.Column(c).Width(dialogRegular).Gap(10).Children(func() {
			dialogHeader(c, "内网 DNS 诊断", d.name+" · "+d.summary)
			ui.Field(c, "内网域名", func() { ui.TextInput(c, &d.domain).Placeholder("db.corp.example") })
			ui.Field(c, "查询类型", func() { ui.Select(c, &d.kind, []string{"A", "AAAA", "CNAME", "TXT", "MX", "SRV"}) })
			ui.Checkbox(c, &d.capture, "旧版 IP 授权兼容检查（不验证当前接管映射）")
			ui.Checkbox(c, &d.automatic, "按资源归属查询（应用域名默认 DNS 归属）")
			if ui.Button(c, "预览 DNS 归属").FontSize(11).Clicked() {
				id := d.id
				if d.automatic {
					id = ""
				}
				d.result = formatRouteDecision(a.mgr.PreviewDNS(d.domain, id))
			}
			ui.Text(c, "查询使用当前 VPN 的 DNS；公网名称不会被转发。此工具不修改系统 DNS，解析成功也不代表业务端口已经可用。").FontSize(11).TextColor(c.Theme().TextMuted).Wrap()
			ui.Field(c, "接管 TCP 检查端口", func() { ui.TextInput(c, &d.port) })
			ui.Row(c).Gap(8).Children(func() {
				if ui.Button(c, "检查运行中映射 DNS").FontSize(11).Disabled(d.running).Clicked() {
					a.startMappedProbe(false)
				}
				if ui.Button(c, "检查映射 DNS 并连接 TCP").FontSize(11).Disabled(d.running).Clicked() {
					a.startMappedProbe(true)
				}
			})
			if d.result != "" {
				ui.Scroll(c).MaxHeight(210).Children(func() { ui.Text(c, d.result).FontSize(13).Wrap() })
			}
			dialogFooter(c, func() {
				if d.running {
					ui.Spinner(c)
					ui.Text(c, "查询中…").FontSize(11).TextColor(c.Theme().TextMuted)
				}
				ui.Row(c).Grow(1)
				if ui.Button(c, "关闭").FontSize(11).Clicked() {
					d.open = false
				}
				if ui.PrimaryButton(c, "查询").Label("查询 DNS").FontSize(11).Disabled(d.running).Clicked() {
					a.startDNSProbe()
				}
			})
		})
	})
	if !d.open && d.cancel != nil {
		d.cancel()
	}
}

func (a *app) startMappedProbe(tcp bool) {
	d := &a.dnsProbe
	packet, err := dnsProbeQuestion(d.domain, "A")
	if err != nil {
		d.result = err.Error()
		return
	}
	port := 443
	if tcp {
		port, err = parsePort(d.port, "检查端口")
		if err != nil {
			d.result = err.Error()
			return
		}
	}
	if a.local == nil {
		d.result = "未启用接管，无法检查实际映射链路"
		return
	}
	connection, err := a.mgr.LocalAppConnection(d.id)
	if err != nil {
		d.result = err.Error()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	replies := make(chan string, 1)
	d.cancel, d.replies, d.running = cancel, replies, true
	go func() {
		defer cancel()
		answer, err := a.local.ExchangeRunningMappedDNS(ctx, connection.Key, packet)
		if err != nil {
			replies <- "运行中映射检查失败：" + err.Error()
			a.invalidate()
			return
		}
		result := "运行中映射 DNS（包含助手发布确认）：\n" + dnsProbeResult(answer, nil, false)
		result += "\n此检查使用接管服务的 DNS 入口；系统 NRPT / 应用自有 DNS 是否命中仍需实机验证。"
		if tcp {
			m := new(dns.Msg)
			m.Unpack(answer)
			address := ""
			for _, rr := range m.Answer {
				if rr, ok := rr.(*dns.A); ok {
					address = rr.A.String()
					break
				}
			}
			if address == "" {
				result += "\nTCP：未尝试，没有可用映射地址"
			} else {
				started := time.Now()
				conn, e := connection.Dial(ctx, "tcp", net.JoinHostPort(address, strconv.Itoa(port)))
				if e != nil {
					result += "\nTCP：建立失败（详情见访问日志）"
				} else {
					conn.Close()
					result += fmt.Sprintf("\nTCP：已通过所属网关建立，用时 %s；未验证应用业务操作", time.Since(started).Round(time.Millisecond))
				}
			}
		}
		replies <- result
		a.invalidate()
	}()
}
