package relay

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ClientOptions configures the importing side.
type ClientOptions struct {
	Code     ShareCode
	Dial     Dialer
	ClientID string
	Name     string
}

// Client is the importing side of a share: pinned TLS, control requests and
// CONNECT tunnels. It never falls back to the original network for a target the
// share owns.
type Client struct {
	code      ShareCode
	transport *http.Transport
	http      *http.Client
	tlsConfig *tls.Config
	dial      Dialer
	clientID  string
	name      string
	base      string
}

// SessionState is the authenticated view of the share.
type SessionState struct {
	ShareID          string
	ServerInstanceID string
	ClientID         string
	Epoch            uint64
	Revision         string
	Capabilities     Capabilities
	Lease            time.Duration
	Resources        *ResourceSnapshot
}

// NewClient prepares the pinned transport. It performs no authentication and no
// network request: preview stays local.
func NewClient(opts ClientOptions) (*Client, error) {
	if opts.Code.Host == "" || opts.Code.Port == 0 {
		return nil, errors.New("分享地址无效")
	}
	if opts.Code.Version != ShareVersion {
		return nil, NewError(CodeProtocolUnsupported, "分享协议版本 %d 不受支持", opts.Code.Version)
	}
	dial := opts.Dial
	if dial == nil {
		dial = DirectDialer
	}
	tlsConfig, err := ClientTLSConfig(opts.Code.Fingerprint, opts.Code.Host)
	if err != nil {
		return nil, err
	}
	transport, err := NewClientTransport(ClientTransportOptions{Fingerprint: opts.Code.Fingerprint, Host: opts.Code.Host, Dial: dial})
	if err != nil {
		return nil, err
	}
	clientID := opts.ClientID
	if clientID == "" {
		clientID = randomClientID()
	}
	return &Client{
		code:      opts.Code,
		transport: transport,
		tlsConfig: tlsConfig,
		dial:      dial,
		clientID:  clientID,
		name:      opts.Name,
		base:      "https://" + opts.Code.Address(),
		http: &http.Client{
			Transport: transport,
			// A redirect would leak the bearer token to another origin.
			CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("分享主机返回了重定向") },
		},
	}, nil
}

// Close releases idle connections.
func (c *Client) Close() {
	if c.transport != nil {
		c.transport.CloseIdleConnections()
	}
}

// Code returns the parsed share code.
func (c *Client) Code() ShareCode { return c.code }

// Open authenticates and fetches the first snapshot. The caller must treat a
// failure as "the node is not online".
func (c *Client) Open(ctx context.Context) (*SessionState, string, error) {
	return c.authenticate(ctx)
}

// setHeaders adds the protocol headers. The Authorization header is added by the
// caller-specific helper so a request can never accidentally carry the share
// token where a client token is expected.
func (c *Client) setHeaders(req *http.Request) {
	req.Header.Set(HeaderProtocol, itoa(ProtocolVersion))
	req.Header.Set(HeaderShareID, c.code.ShareID)
	req.Header.Set(HeaderRequestID, randomRequestID())
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cache-Control", "no-store")
}

func decodeError(status int, data []byte) error {
	var wire struct {
		Code      Code   `json:"code"`
		Message   string `json:"message"`
		Retryable bool   `json:"retryable"`
		RequestID string `json:"requestId"`
	}
	if err := json.Unmarshal(data, &wire); err == nil && wire.Code != "" {
		return &Error{Code: wire.Code, Message: wire.Message, Retryable: wire.Retryable, RequestID: wire.RequestID, Status: status}
	}
	return &Error{Code: CodeForStatus(status), Message: fmt.Sprintf("分享主机返回 HTTP %d", status), Retryable: retryableCode(CodeForStatus(status)), Status: status}
}

// password is the share token; it is used only to create a session.
func (c *Client) authenticate(ctx context.Context) (*SessionState, string, error) {
	req := SessionRequest{ClientID: c.clientID, Name: c.name}
	var resp SessionResponse
	if _, err := c.controlWithToken(ctx, http.MethodPost, "/v1/sessions", req, &resp, c.code.Token); err != nil {
		return nil, "", err
	}
	if resp.Version != ProtocolVersion {
		return nil, "", NewError(CodeProtocolUnsupported, "分享协议版本 %d 不受支持", resp.Version)
	}
	if resp.ShareID != c.code.ShareID {
		return nil, "", NewError(CodeInvalidCredentials, "分享身份与口令不一致")
	}
	if resp.ClientToken == "" {
		return nil, "", NewError(CodeInvalidCredentials, "分享主机没有签发会话凭据")
	}
	if err := resp.Capabilities.Validate(); err != nil {
		return nil, "", err
	}
	if resp.Resources == nil {
		return nil, "", NewError(CodeInvalidRequest, "分享主机没有返回资源快照")
	}
	if err := resp.Resources.Validate(); err != nil {
		return nil, "", err
	}
	lease := time.Duration(resp.LeaseSeconds) * time.Second
	if lease <= 0 {
		lease = ClientLease
	}
	state := &SessionState{
		ShareID:          resp.ShareID,
		ServerInstanceID: resp.ServerInstanceID,
		ClientID:         resp.ClientID,
		Epoch:            resp.Epoch,
		Revision:         resp.Revision,
		Capabilities:     resp.Capabilities,
		Lease:            lease,
		Resources:        resp.Resources,
	}
	return state, resp.ClientToken, nil
}

func (c *Client) controlWithToken(ctx context.Context, method, path string, body, out any, token string) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		if len(data) > MaxSessionBody {
			return nil, NewError(CodeInvalidRequest, "请求体超过上限")
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return nil, err
	}
	c.setHeaders(req)
	req.Header.Set(HeaderAuthorization, "Bearer "+token)
	resp, err := c.http.Do(req)
	if err != nil {
		var nerr net.Error
		if errors.As(err, &nerr) && nerr.Timeout() {
			return nil, NewError(CodeDialTimeout, "连接分享主机超时")
		}
		return nil, NewError(CodeTargetUnreachable, "%s", describeHostDialFailure(err))
	}
	defer resp.Body.Close()
	data, err := readBounded(resp.Body, MaxSnapshotBytes+MaxErrorBody)
	if err != nil {
		return resp, err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotModified {
		return resp, decodeError(resp.StatusCode, data)
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return resp, NewError(CodeInvalidRequest, "分享主机响应无法解析")
		}
	}
	return resp, nil
}

// Status is the heartbeat. It renews the lease and reports the current epoch and
// revision so the caller can decide whether to refetch resources.
func (c *Client) Status(ctx context.Context, token string) (*StatusResponse, error) {
	var resp StatusResponse
	if _, err := c.controlWithToken(ctx, http.MethodGet, "/v1/status", nil, &resp, token); err != nil {
		return nil, err
	}
	if resp.Version != ProtocolVersion {
		return nil, NewError(CodeProtocolUnsupported, "分享协议版本已变化")
	}
	return &resp, nil
}

// describeHostDialFailure turns a transport-level failure to reach the share host
// into a sentence the colleague can act on. The raw error text mixes the HTTP
// verb, the URL and the operating system's wording ("connection refused" on
// Unix, "actively refused" on Windows); none of that says whether the host
// stopped sharing, is on another network, or is being filtered.
func describeHostDialFailure(err error) string {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "connection refused"), strings.Contains(msg, "actively refused"):
		return "分享主机拒绝了连接：共享可能已关闭，或宿主已退出"
	case strings.Contains(msg, "no route to host"), strings.Contains(msg, "network is unreachable"),
		strings.Contains(msg, "host is down"):
		return "分享主机不可达：双方不在同一网段，或宿主的网络被系统归为「公用」/防火墙未放行"
	case strings.Contains(msg, "connection reset"), strings.Contains(msg, "forcibly closed"):
		return "分享主机重置了连接"
	case strings.Contains(msg, "i/o timeout"), strings.Contains(msg, "deadline exceeded"):
		return "连接分享主机超时"
	default:
		return "无法连接分享主机"
	}
}

// quoteEntityTag renders a revision as an If-None-Match entity tag. The server
// compares against the quoted form (RFC 7232), so a caller passing the bare
// revision would otherwise never match and would always receive the full
// snapshot - a conditional refresh that silently never was conditional.
func quoteEntityTag(v string) string {
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		return v
	}
	return `"` + v + `"`
}

// Resources fetches a complete snapshot. etag may be empty.
func (c *Client) Resources(ctx context.Context, token, etag string) (*ResourcesResponse, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/v1/resources", nil)
	if err != nil {
		return nil, false, err
	}
	c.setHeaders(req)
	req.Header.Set(HeaderAuthorization, "Bearer "+token)
	if etag != "" {
		req.Header.Set(HeaderIfNoneMatch, quoteEntityTag(etag))
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, false, NewError(CodeTargetUnreachable, "%s", describeHostDialFailure(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return nil, true, nil
	}
	data, err := readBounded(resp.Body, MaxSnapshotBytes+MaxErrorBody)
	if err != nil {
		return nil, false, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, decodeError(resp.StatusCode, data)
	}
	var out ResourcesResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, false, NewError(CodeInvalidRequest, "资源快照无法解析")
	}
	if out.Resources == nil {
		return nil, false, NewError(CodeInvalidRequest, "资源快照缺失")
	}
	if err := out.Resources.Validate(); err != nil {
		return nil, false, err
	}
	return &out, false, nil
}

// ExchangeDNS asks the sharing host to resolve one internal name. The body is a
// raw DNS message; epoch and revision travel in the protocol headers, so a stale
// client is refused instead of being served from newer authorization.
func (c *Client) ExchangeDNS(ctx context.Context, token string, epoch uint64, revision string, query []byte) ([]byte, error) {
	if len(query) == 0 || len(query) > MaxDNSBody {
		return nil, NewError(CodeInvalidRequest, "DNS 查询大小无效")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/v1/dns-query", bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	c.setHeaders(req)
	req.Header.Set("Content-Type", DNSMediaType)
	req.Header.Set(HeaderAuthorization, "Bearer "+token)
	req.Header.Set(HeaderShareEpoch, itoa(int(epoch)))
	if revision != "" {
		req.Header.Set(HeaderResourceRev, revision)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, NewError(CodeTargetUnreachable, "%s", describeHostDialFailure(err))
	}
	defer resp.Body.Close()
	answer, err := readBounded(resp.Body, MaxDNSBody+MaxErrorBody)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, decodeError(resp.StatusCode, answer)
	}
	return answer, nil
}

// Revoke ends this client session and its tunnels. It is best effort: a share
// that is already gone has nothing to revoke.
func (c *Client) Revoke(ctx context.Context, token string) error {
	_, err := c.controlWithToken(ctx, http.MethodDelete, "/v1/sessions/current", nil, nil, token)
	return err
}

// Dial opens one strict tunnel. It returns only after the sharing host answered
// 200, so a refusal never looks like a working connection.
func (c *Client) Dial(ctx context.Context, token string, epoch uint64, revision, target string) (net.Conn, error) {
	conn, err := c.dial(ctx, "tcp", c.code.Address())
	if err != nil {
		return nil, NewError(CodeTargetUnreachable, "%s", describeHostDialFailure(err))
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	tlsConn := tls.Client(conn, c.tlsConfig.Clone())
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, NewError(CodeInvalidCredentials, "分享主机身份验证失败：%v", err)
	}
	req := &http.Request{
		Method:     http.MethodConnect,
		URL:        &url.URL{Host: target},
		Host:       target,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{},
	}
	c.setHeaders(req)
	req.Header.Set(HeaderAuthorization, "Bearer "+token)
	req.Header.Set(HeaderShareEpoch, fmt.Sprintf("%d", epoch))
	req.Header.Set(HeaderResourceRev, revision)
	req.Header.Del("Content-Type")
	if err := req.Write(tlsConn); err != nil {
		_ = tlsConn.Close()
		return nil, NewError(CodeTargetUnreachable, "发送分享请求失败：%v", err)
	}
	reader := bufioReader(tlsConn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		_ = tlsConn.Close()
		return nil, NewError(CodeTargetUnreachable, "分享主机响应无效：%v", err)
	}
	if resp.StatusCode != http.StatusOK {
		data, _ := readBounded(resp.Body, MaxErrorBody)
		_ = resp.Body.Close()
		_ = tlsConn.Close()
		return nil, decodeError(resp.StatusCode, data)
	}
	_ = tlsConn.SetDeadline(time.Time{})
	return WrapBuffered(tlsConn, reader), nil
}

func randomClientID() string {
	var b [16]byte
	if _, err := randRead(b[:]); err != nil {
		return "client-" + itoa(int(time.Now().UnixNano()%1_000_000_000))
	}
	return base64URL(b[:])
}

func randomRequestID() string {
	var b [12]byte
	if _, err := randRead(b[:]); err != nil {
		return "req"
	}
	return base64URL(b[:])
}
