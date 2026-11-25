package relay

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// Stage is one layer of the connection check. The order is fixed so a user can
// see where a failure starts.
type Stage string

const (
	StageInput     Stage = "input"
	StageTCP       Stage = "tcp"
	StageTLS       Stage = "tls"
	StageAuth      Stage = "auth"
	StageResources Stage = "resources"
	StageBusiness  Stage = "business"
)

// Step is one observed fact. Uncertain is true when the check could not prove
// the cause: a timeout is not a firewall verdict.
type Step struct {
	Stage     Stage
	OK        bool
	Skipped   bool
	Detail    string
	Uncertain bool
}

// Report is the layered diagnostic result.
type Report struct {
	Steps      []Step
	Conclusion string
}

// Failed reports whether any executed step failed.
func (r Report) Failed() bool {
	for _, s := range r.Steps {
		if !s.OK && !s.Skipped {
			return true
		}
	}
	return false
}

// DiagnoseOptions configures a layered check.
type DiagnoseOptions struct {
	Dial Dialer
	// Target optionally probes one business target through the share.
	Target string
	// Timeout bounds each network step; zero means 5 seconds.
	Timeout time.Duration
}

// Diagnose runs the layered check: input → TCP → TLS identity → auth →
// resources → optional business target. It reports what was observed and marks
// timeouts as uncertain instead of blaming the firewall.
func Diagnose(ctx context.Context, code ShareCode, opts DiagnoseOptions) Report {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = TLSHandshakeTimeout
	}
	dial := opts.Dial
	if dial == nil {
		dial = DirectDialer
	}
	var report Report
	add := func(step Step) { report.Steps = append(report.Steps, step) }

	// Input: the code was already parsed by the caller, but the address must
	// still be usable.
	if code.Host == "" || code.Port <= 0 || code.Port > 65535 {
		add(Step{Stage: StageInput, Detail: "分享口令缺少有效地址"})
		report.Conclusion = "口令不完整，请重新复制当前版本的分享口令"
		return report
	}
	add(Step{Stage: StageInput, OK: true, Detail: code.Address()})

	// TCP: connection refused and timeout mean different things.
	tcpCtx, cancel := context.WithTimeout(ctx, timeout)
	conn, err := dial(tcpCtx, "tcp", code.Address())
	cancel()
	if err != nil {
		detail, uncertain := describeDialError(err, timeout)
		add(Step{Stage: StageTCP, Detail: detail, Uncertain: uncertain})
		report.Conclusion = "无法建立到分享主机的 TCP 连接"
		return report
	}
	add(Step{Stage: StageTCP, OK: true, Detail: "TCP 连接已建立"})

	// TLS: identity pinning. A mismatch is a definite answer; a timeout or a
	// non-TLS peer is not.
	tlsConfig, err := ClientTLSConfig(code.Fingerprint, code.Host)
	if err != nil {
		_ = conn.Close()
		add(Step{Stage: StageTLS, Detail: err.Error()})
		report.Conclusion = "分享口令中的证书指纹无效"
		return report
	}
	tlsConn := tls.Client(conn, tlsConfig)
	hsCtx, hsCancel := context.WithTimeout(ctx, timeout)
	err = tlsConn.HandshakeContext(hsCtx)
	hsCancel()
	if err != nil {
		_ = conn.Close()
		detail, uncertain := describeTLSError(err)
		add(Step{Stage: StageTLS, Detail: detail, Uncertain: uncertain})
		report.Conclusion = "无法验证分享主机身份"
		return report
	}
	add(Step{Stage: StageTLS, OK: true, Detail: "证书指纹与口令一致"})
	_ = tlsConn.Close()

	// Auth and resources need the protocol client.
	client, err := NewClient(ClientOptions{Code: code, Dial: dial})
	if err != nil {
		add(Step{Stage: StageAuth, Detail: err.Error()})
		report.Conclusion = "无法创建分享客户端"
		return report
	}
	defer client.Close()
	authCtx, authCancel := context.WithTimeout(ctx, FirstConnectBudget)
	state, token, err := client.Open(authCtx)
	authCancel()
	if err != nil {
		detail, uncertain := describeProtocolError(err)
		add(Step{Stage: StageAuth, Detail: detail, Uncertain: uncertain})
		report.Conclusion = "认证失败"
		return report
	}
	add(Step{Stage: StageAuth, OK: true, Detail: "分享登录成功"})

	if err := state.Resources.Validate(); err != nil {
		add(Step{Stage: StageResources, Detail: err.Error()})
		report.Conclusion = "分享主机返回的资源快照无法校验"
		return report
	}
	// Say whether DNS comes with the share. A snapshot without a DNS server is
	// not a failure, but a colleague who then cannot resolve an intranet name has
	// no way to tell "no DNS offered" from "DNS broken" unless this line says it.
	add(Step{Stage: StageResources, OK: true, Detail: fmt.Sprintf("已同步 %d 条资源规则（代次 %d）%s",
		state.Resources.EntryCount(), state.Epoch, dnsNote(state.Resources))})

	if strings.TrimSpace(opts.Target) != "" {
		dialCtx, dialCancel := context.WithTimeout(ctx, timeout)
		business, err := client.Dial(dialCtx, token, state.Epoch, state.Revision, opts.Target)
		dialCancel()
		if err != nil {
			detail, uncertain := describeProtocolError(err)
			add(Step{Stage: StageBusiness, Detail: opts.Target + "：" + detail, Uncertain: uncertain})
			report.Conclusion = "主机可达，但这个目标的业务连接没有建立"
			return report
		}
		_ = business.Close()
		add(Step{Stage: StageBusiness, OK: true, Detail: opts.Target + "：业务连接已建立"})
		report.Conclusion = "主机、身份、认证、资源与业务目标均可达"
		return report
	}
	report.Conclusion = "主机、身份、认证与资源同步均正常"
	return report
}

// describeDialError separates "refused" from "did not answer in time".
func describeDialError(err error, timeout time.Duration) (string, bool) {
	var dnsErr *net.DNSError
	var opErr *net.OpError
	switch {
	case errors.As(err, &dnsErr):
		return "地址无法解析：" + dnsErr.Err, false
	case errors.Is(err, context.DeadlineExceeded) || errors.As(err, &opErr) && opErr.Timeout():
		return fmt.Sprintf("在 %s 内未建立连接；原因未唯一确定（可能是防火墙、AP 隔离、地址变化或对方已关闭共享）", timeout), true
	}
	lower := strings.ToLower(err.Error())
	if strings.Contains(lower, "refused") || strings.Contains(lower, "拒绝") {
		return "对端拒绝连接；请先确认分享主机正在运行，再检查防火墙", false
	}
	return "TCP 连接失败：" + err.Error(), true
}

// describeTLSError classifies identity failures. Only an explicit pin mismatch
// is a definite verdict.
func describeTLSError(err error) (string, bool) {
	message := err.Error()
	lower := strings.ToLower(message)
	switch {
	case strings.Contains(message, "指纹不匹配"), strings.Contains(message, "证书"):
		return message, false
	case strings.Contains(lower, "first record does not look like a tls handshake"),
		strings.Contains(lower, "record header"):
		return "对端端口不是分享主机的 TLS 服务，请核对地址与端口", false
	case errors.Is(err, context.DeadlineExceeded):
		return "TLS 握手超时；原因未唯一确定", true
	}
	return "TLS 握手失败：" + message, true
}

// describeProtocolError turns a wire error into a fact plus an uncertainty flag.
func describeProtocolError(err error) (string, bool) {
	var re *Error
	if errors.As(err, &re) {
		switch re.Code {
		case CodeInvalidCredentials:
			return "分享口令无效或已被撤销，请向主机获取新口令", false
		case CodeShareClosed:
			return "分享已关闭", false
		case CodeProtocolUnsupported:
			return "分享主机协议版本不兼容，请升级客户端", false
		case CodeResourceDenied:
			return "该目标不在分享范围内", false
		case CodeStaleResources:
			return "资源版本已变化，请重试", false
		case CodeBusy:
			return "分享主机繁忙，请稍后再试", true
		case CodeDialTimeout:
			return "分享主机连接目标超时", true
		case CodeTargetUnreachable:
			return re.Message, true
		case CodeVPNUnavailable:
			return "分享主机的 VPN 接入点不可用", false
		}
		return re.Message, re.Retryable
	}
	return err.Error(), true
}

// FormatReport renders a report as the lines the UI shows.
func FormatReport(report Report) []string {
	out := make([]string, 0, len(report.Steps)+1)
	labels := map[Stage]string{
		StageInput: "口令", StageTCP: "TCP", StageTLS: "身份", StageAuth: "认证",
		StageResources: "资源", StageBusiness: "业务",
	}
	for _, step := range report.Steps {
		mark := "✓"
		if !step.OK {
			mark = "✕"
		}
		if step.Skipped {
			mark = "–"
		}
		line := fmt.Sprintf("%s %s：%s", mark, labels[step.Stage], step.Detail)
		if step.Uncertain {
			line += "（原因不确定）"
		}
		out = append(out, line)
	}
	if report.Conclusion != "" {
		out = append(out, "结论："+report.Conclusion)
	}
	return out
}
