package wincapture

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/ehzyil/connect-hub/internal/dnsmapping"
	"github.com/ehzyil/connect-hub/internal/packetstack"
	"github.com/ehzyil/connect-hub/internal/proxy"
	"github.com/ehzyil/connect-hub/internal/workeripc"
	"github.com/miekg/dns"
	tun "github.com/mythologyli/sing-tun"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	proxy2 "golang.org/x/net/proxy"
	"golang.org/x/sys/windows"
)

type registration struct {
	session string
	job     windows.Handle
	dial    *proxy.SOCKSDialer
	ctx     context.Context
	cancel  context.CancelFunc
}
type aliasEntry struct {
	original netip.Addr
	expires  time.Time
}

type captureSession struct {
	system     *registration
	config     Config
	aliases    netip.Prefix
	resources  []netip.Prefix
	gateways   []netip.Addr
	mappings   map[netip.Addr]aliasEntry
	issued     map[netip.Addr]netip.Addr
	rules      ruleSet
	retired    bool
	undoAlias  func() error
	aliasFlows int
	ctx        context.Context
	cancel     context.CancelFunc
}

type engine struct {
	original       *proxy.Server
	originalInfo   Upstream
	system         *registration
	systemInfo     Upstream
	mu             sync.Mutex
	ctx            context.Context
	cancel         context.CancelFunc
	tun            tun.WinTun
	stack          tun.Stack
	index          uint32
	installRoute   func(netip.Prefix) (func() error, error)
	reserveMapping func(string, string, time.Time) error
	adapter        netip.Prefix
	dnsAddress     netip.Addr
	id             string
	parent         windows.Handle
	apps           map[string]*registration
	sessions       map[string]*captureSession
	shared         sharedRules
	dnsPolicy      dnsPolicy
	lastDNSCheck   time.Time
	slots          chan struct{}
	once           sync.Once
	closeErr       error
	drainOnce      sync.Once
	drainErr       error
}

func newEngine(ctx context.Context, id string, parent windows.Handle, sessionID string, config Config) (_ *engine, err error) {
	if !validID(sessionID) {
		return nil, errors.New("VPN 接管会话标识无效")
	}
	if err = config.validate(); err != nil {
		return nil, err
	}
	resources, err := ResourcePrefixes(config.Networks)
	if err != nil {
		return nil, fmt.Errorf("解析 VPN 资源范围：%w", err)
	}
	resolveCtx, resolveCancel := context.WithTimeout(ctx, 5*time.Second)
	gateways, err := net.DefaultResolver.LookupNetIP(resolveCtx, "ip4", config.Gateway)
	resolveCancel()
	if err != nil || len(gateways) == 0 {
		return nil, errors.New("无法确认 VPN 网关的原出口，尚未修改网络")
	}
	for _, gateway := range gateways {
		for _, p := range resources {
			if p.Contains(gateway.Unmap()) {
				return nil, errors.New("VPN 资源覆盖了网关自身地址，请使用显式代理")
			}
		}
	}
	lockCtx, lockCancel := context.WithTimeout(ctx, 20*time.Second)
	unlock, err := networkTransaction(lockCtx)
	lockCancel()
	if err != nil {
		return nil, fmt.Errorf("准备接管网络事务：%w", err)
	}
	defer unlock()
	existing, err := routeRows()
	if err != nil {
		return nil, fmt.Errorf("检查当前网络路由：%w", err)
	}
	for _, p := range resources {
		for _, r := range existing {
			if r.Prefix.Overlaps(p) && r.Prefix.Bits() >= p.Bits() {
				return nil, fmt.Errorf("VPN 资源 %s 与现有更具体或等长路由重叠，请对该资源使用显式代理", p)
			}
		}
	}
	allocationRoutes := append([]Route(nil), existing...)
	retired, err := loadMappingReservations(time.Now())
	if err != nil {
		return nil, fmt.Errorf("读取映射退役记录：%w", err)
	}
	for _, prefix := range retired {
		allocationRoutes = append(allocationRoutes, Route{Prefix: prefix})
	}
	for _, raw := range config.ReservedPools {
		allocationRoutes = append(allocationRoutes, Route{Prefix: netip.MustParsePrefix(raw)})
	}
	addresses, addressErr := net.InterfaceAddrs()
	if addressErr != nil {
		return nil, addressErr
	}
	for _, address := range addresses {
		if prefix, e := netip.ParsePrefix(address.String()); e == nil && prefix.Addr().Is4() {
			for _, resource := range resources {
				if resource.Contains(prefix.Addr()) {
					return nil, errors.New("VPN 资源覆盖本机接口地址，请缩小捕获范围")
				}
			}
			allocationRoutes = append(allocationRoutes, Route{Prefix: netip.PrefixFrom(prefix.Addr(), 32)})
		}
	}
	adapter, aliases, err := choosePrefixes(allocationRoutes, resources)
	if err != nil {
		return nil, err
	}
	occupied := append([]netip.Prefix(nil), resources...)
	occupied = append(occupied, adapter)
	for _, r := range allocationRoutes {
		if r.Prefix.Bits() >= 15 {
			occupied = append(occupied, r.Prefix)
		}
	}
	aliases, err = dnsmapping.Choose(occupied, config.AliasNetworks)
	if err != nil {
		return nil, err
	}
	life, cancel := context.WithCancel(ctx)
	e := &engine{ctx: life, cancel: cancel, adapter: adapter, dnsAddress: adapter.Addr().Next().Next(),
		id: id, parent: parent, apps: map[string]*registration{}, sessions: map[string]*captureSession{}, shared: sharedRules{}, slots: make(chan struct{}, 512)}
	e.dnsPolicy.apply = func(before, after []string) error {
		return updateNRPT(e.ctx, e.id, before, after, e.dnsAddress.String())
	}
	e.reserveMapping = saveMappingReservation
	defer func() {
		if err != nil {
			_ = e.Close()
		}
	}()
	name := "ECH-" + id[:12]
	// With no Inet*Address/AutoRoute, sing-tun creates the adapter/session
	// without setting DNS or installing a default route. Configure our own
	// address and limited routes explicitly using IP Helper APIs.
	e.tun, err = tun.New(tun.Options{Name: name, MTU: packetstack.MTU})
	if err != nil {
		return nil, windowsError("创建 Wintun 接管网卡", err)
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, windowsError("查找 Wintun 接管网卡", err)
	}
	e.index = uint32(iface.Index)
	e.installRoute = func(p netip.Prefix) (func() error, error) {
		row, err := addRoute(e.index, p)
		if row == nil {
			return nil, err
		}
		return func() error { return removeRoute(row) }, err
	}
	if err = configureAdapter(e.index, netip.PrefixFrom(adapter.Addr().Next(), adapter.Bits())); err != nil {
		return nil, err
	}
	if err = e.startOriginalExit(); err != nil {
		return nil, err
	}
	e.stack = packetstack.New(life, wintunPackets{e.tun}, e)
	if err = e.stack.Start(); err != nil {
		e.stack = nil
		return nil, fmt.Errorf("启动接管网络栈：%w", err)
	}
	if err = e.registerPrepared(sessionID, config, aliases, resources, gateways); err != nil {
		return nil, err
	}
	return e, nil
}

func (e *engine) attach(sessionID string, request *attach) error {
	if request == nil || !validID(request.ID) || request.Job == 0 {
		return errors.New("软件启动身份无效")
	}
	if err := request.Upstream.validate(); err != nil {
		return err
	}
	var job windows.Handle
	const jobQuery = 0x0004
	if err := windows.DuplicateHandle(e.parent, windows.Handle(request.Job), windows.CurrentProcess(), &job, jobQuery, false, 0); err != nil {
		return windowsError("登记软件进程组 DuplicateHandle", err)
	}
	keep := false
	defer func() {
		if !keep {
			windows.CloseHandle(job)
		}
	}()
	if err := requireEmptyJob(job); err != nil {
		return fmt.Errorf("检查软件进程组：%w", err)
	}
	dial, err := proxy.NewSOCKSDialer(request.Upstream.Address, &proxy2.Auth{User: request.Upstream.Username, Password: request.Upstream.Password})
	if err != nil {
		return err
	}
	e.mu.Lock()
	session := e.sessions[sessionID]
	if session == nil || session.retired {
		e.mu.Unlock()
		return errors.New("VPN 接管会话不存在或已退役")
	}
	if len(e.apps) >= 16 || e.apps[request.ID] != nil {
		e.mu.Unlock()
		return errors.New("软件接管项目过多或已存在")
	}
	first := true
	for _, app := range e.apps {
		if app.session == sessionID {
			first = false
			break
		}
	}
	e.mu.Unlock()
	if first {
		if err := e.enableRules(session); err != nil {
			return fmt.Errorf("启用软件接管规则：%w", err)
		}
	}
	ctx, cancel := context.WithCancel(session.ctx)
	e.mu.Lock()
	e.apps[request.ID] = &registration{session: sessionID, job: job, dial: dial, ctx: ctx, cancel: cancel}
	e.mu.Unlock()
	keep = true
	return nil
}

func sameOrdinaryUser(parent, child windows.Handle) error {
	var a, b windows.Token
	if err := windows.OpenProcessToken(parent, windows.TOKEN_QUERY, &a); err != nil {
		return err
	}
	defer a.Close()
	if err := windows.OpenProcessToken(child, windows.TOKEN_QUERY, &b); err != nil {
		return err
	}
	defer b.Close()
	ua, ea := a.GetTokenUser()
	ub, eb := b.GetTokenUser()
	if ea != nil || eb != nil {
		return errors.Join(ea, eb)
	}
	if b.IsElevated() || !ua.User.Sid.Equals(ub.User.Sid) {
		return errors.New("只能接管当前用户以普通权限启动的软件")
	}
	return nil
}

func (e *engine) detach(sessionID, id string) error {
	e.mu.Lock()
	if app := e.apps[id]; app != nil {
		if app.session != sessionID {
			e.mu.Unlock()
			return errors.New("软件不属于指定 VPN 会话")
		}
		delete(e.apps, id)
		app.cancel()
		windows.CloseHandle(app.job)
	}
	last := true
	for _, app := range e.apps {
		if app.session == sessionID {
			last = false
			break
		}
	}
	session := e.sessions[sessionID]
	if session != nil && session.system != nil {
		last = false
	}
	e.mu.Unlock()
	if last && session != nil {
		return session.rules.Disable()
	}
	return nil
}

func (e *engine) publish(sessionID string, aliases []workeripc.DNSAlias) error {
	if len(aliases) > 256 {
		return errors.New("DNS 映射数量过多")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	session := e.sessions[sessionID]
	if session == nil || session.retired {
		return errors.New("VPN 接管会话不存在或已退役")
	}
	now := time.Now()
	for addr, entry := range session.mappings {
		if !now.Before(entry.expires) {
			delete(session.mappings, addr)
		}
	}
	updates := map[netip.Addr]aliasEntry{}
	if session.issued == nil {
		session.issued = make(map[netip.Addr]netip.Addr)
	}
	for _, alias := range aliases {
		a, ea := netip.ParseAddr(alias.Address)
		o, eo := netip.ParseAddr(alias.Original)
		if ea != nil || eo != nil || !session.aliases.Contains(a) || !o.Is4() || !o.IsGlobalUnicast() || o.IsLoopback() || o.IsLinkLocalUnicast() || netip.MustParsePrefix("198.18.0.0/15").Contains(o) || alias.TTL == 0 || alias.TTL > 60 {
			return errors.New("DNS 映射超出本次会话范围")
		}
		if old, ok := session.mappings[a]; ok && old.original != o {
			return errors.New("DNS 映射在有效期内发生冲突")
		}
		if original, ok := session.issued[a]; ok && original != o {
			return errors.New("已发布映射不能改变原始地址")
		}
		if old, ok := updates[a]; ok && old.original != o {
			return errors.New("重复 DNS 映射冲突")
		}
		newExpires := now.Add(time.Duration(alias.TTL) * time.Second)
		if old, ok := session.mappings[a]; ok && old.expires.After(newExpires) {
			newExpires = old.expires
		}
		if old, ok := updates[a]; ok && old.expires.After(newExpires) {
			newExpires = old.expires
		}
		updates[a] = aliasEntry{o, newExpires}
	}
	newEntries := 0
	for addr := range updates {
		if _, ok := session.mappings[addr]; !ok {
			newEntries++
		}
	}
	if len(session.mappings)+newEntries > 8192 {
		return errors.New("DNS 映射表已满")
	}
	if len(updates) > 0 {
		if e.reserveMapping == nil {
			return errors.New("映射退役记录服务未就绪")
		}
		var expires time.Time
		for _, entry := range updates {
			if entry.expires.After(expires) {
				expires = entry.expires
			}
		}
		if err := e.reserveMapping(sessionID, session.aliases.String(), expires); err != nil {
			return errors.New("无法保存映射退役记录，拒绝发布 DNS 答案")
		}
	}
	for addr, entry := range updates {
		session.mappings[addr] = entry
		session.issued[addr] = entry.original
	}
	return nil
}

func (e *engine) selectApp(owner *Owner) (*registration, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	var selected *registration
	for _, app := range e.apps {
		member, err := owner.InJob(app.job)
		if err != nil {
			return nil, err
		}
		if member {
			if err := sameOrdinaryUser(e.parent, owner.handle); err != nil {
				return nil, err
			}
			if selected != nil {
				return nil, ErrOwnerAmbiguous
			}
			selected = app
		}
	}
	return selected, nil
}

func (e *engine) originalTarget(destination netip.AddrPort) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if netip.MustParsePrefix("198.19.0.0/16").Contains(destination.Addr()) {
		found := false
		for _, session := range e.sessions {
			if !session.aliases.Contains(destination.Addr()) {
				continue
			}
			entry, ok := session.mappings[destination.Addr()]
			if session.retired || !ok || !time.Now().Before(entry.expires) {
				return "", errors.New("DNS 映射已过期，请重新解析域名")
			}
			destination = netip.AddrPortFrom(entry.original, destination.Port())
			found = true
			break
		}
		if !found {
			return "", errors.New("未知 DNS 映射地址")
		}
	}
	if e.adapter.Contains(destination.Addr()) {
		return "", errors.New("不允许转发到捕获适配器自身")
	}
	return destination.String(), nil
}

func (e *engine) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	defer conn.Close()
	select {
	case e.slots <- struct{}{}:
		defer func() { <-e.slots }()
	default:
		return errors.New("接管连接数已达上限")
	}
	if metadata.Destination.Addr == e.dnsAddress && metadata.Destination.Port == 53 {
		return e.serveDNSTCP(ctx, conn)
	}
	releaseAlias, err := e.holdAlias(metadata.Destination.Addr)
	if err != nil {
		return err
	}
	if releaseAlias != nil {
		defer releaseAlias()
	}
	owner, err := LookupTCP(ctx, Tuple{metadata.Source.AddrPort(), metadata.Destination.AddrPort()})
	if err != nil {
		return err
	}
	if owner.PID == uint32(os.Getpid()) {
		owner.Close()
		return errors.New("检测到网络助手出口回环，已拒绝再次转发")
	}
	app, err := e.selectApp(owner)
	owner.Close()
	if err != nil {
		return err
	}
	var upstream net.Conn
	life := e.ctx
	if app == nil {
		app, err = e.selectSystem(metadata.Destination.Addr)
		if err != nil {
			return err
		}
	}
	if app != nil {
		if app.session != "" {
			if err := e.validateAppTarget(app.session, metadata.Destination.Addr); err != nil {
				return err
			}
		}
		life = app.ctx
		upstream, err = app.dial.DialContext(life, "tcp", metadata.Destination.String())
	} else {
		var address string
		address, err = e.originalTarget(metadata.Destination.AddrPort())
		if err == nil {
			upstream, err = originalDial(life, "tcp4", address, e.index)
		}
	}
	if err != nil {
		return err
	}
	defer upstream.Close()
	stop := context.AfterFunc(life, func() { conn.Close(); upstream.Close() })
	defer stop()
	proxy.Relay(conn, upstream)
	return nil
}

func (e *engine) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	defer conn.Close()
	select {
	case e.slots <- struct{}{}:
		defer func() { <-e.slots }()
	default:
		return errors.New("接管连接数已达上限")
	}
	if metadata.Destination.Addr == e.dnsAddress && metadata.Destination.Port == 53 {
		return e.serveDNSUDP(ctx, conn, metadata.Destination)
	}
	releaseAlias, err := e.holdAlias(metadata.Destination.Addr)
	if err != nil {
		return err
	}
	if releaseAlias != nil {
		defer releaseAlias()
	}
	owner, err := LookupUDP(ctx, metadata.Source.AddrPort())
	if err != nil {
		return err
	}
	if owner.PID == uint32(os.Getpid()) {
		owner.Close()
		return errors.New("检测到网络助手出口回环，已拒绝再次转发")
	}
	app, err := e.selectApp(owner)
	owner.Close()
	if err != nil {
		return err
	}
	if app != nil {
		return errors.New("Windows 软件接管暂不支持内网 UDP，请使用 TCP")
	}
	if system, err := e.selectSystem(metadata.Destination.Addr); err != nil {
		return err
	} else if system != nil {
		upstream, err := system.dial.DialDatagramContext(system.ctx, metadata.Destination.String())
		if err != nil {
			return err
		}
		packetstack.RelayUDP(system.ctx, conn, metadata.Destination, upstream)
		return nil
	}
	address, err := e.originalTarget(metadata.Destination.AddrPort())
	if err != nil {
		return err
	}
	upstream, err := originalDial(e.ctx, "udp4", address, e.index)
	if err != nil {
		return err
	}
	defer upstream.Close()
	stop := context.AfterFunc(e.ctx, func() { conn.Close(); upstream.Close() })
	defer stop()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer conn.Close()
		buffer := make([]byte, 65535)
		for {
			_ = upstream.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, err := upstream.Read(buffer)
			if err != nil {
				return
			}
			b := buf.As(append([]byte(nil), buffer[:n]...))
			if err = conn.WritePacket(b, metadata.Destination); err != nil {
				return
			}
		}
	}()
	defer func() { upstream.Close(); <-done }()
	for {
		b := buf.NewSize(65535)
		_, err = conn.ReadPacket(b)
		if err != nil {
			b.Release()
			return err
		}
		_, err = upstream.Write(b.Bytes())
		b.Release()
		if err != nil {
			return err
		}
	}
}

func (e *engine) NewError(context.Context, error) {
	// Adapter I/O failures end the session on the next control heartbeat.
	// Never emit raw upstream errors or credentials.
	e.cancel()
}

func (e *engine) dnsQuery(ctx context.Context, q *dns.Msg) *dns.Msg {
	fail := func() *dns.Msg { return new(dns.Msg).SetRcode(q, dns.RcodeServerFailure) }
	if q.Response || q.Opcode != dns.OpcodeQuery || len(q.Question) != 1 {
		return fail()
	}
	e.mu.Lock()
	var selected *captureSession
	best, conflict := 0, false
	sharedAddress := ""
	for _, session := range e.sessions {
		if session.config.SharedDNS && !session.retired && len(session.config.Domains) > 0 {
			sharedAddress = session.config.DNSAddress
		}
		for _, domain := range session.config.Domains {
			if !dns.IsSubDomain(domain+".", q.Question[0].Name) {
				continue
			}
			if len(domain) > best {
				selected, best, conflict = session, len(domain), false
			} else if len(domain) == best && selected != session {
				conflict = true
			}
		}
	}
	if selected == nil {
		e.mu.Unlock()
		return new(dns.Msg).SetRcode(q, dns.RcodeRefused)
	}
	if sharedAddress == "" && (conflict || selected.retired) {
		e.mu.Unlock()
		return fail()
	}
	address, life := selected.config.DNSAddress, selected.ctx
	if sharedAddress != "" {
		address, life = sharedAddress, e.ctx
	}
	e.mu.Unlock()
	queryCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(life, cancel)
	defer stop()
	defer cancel()
	answer, _, err := (&dns.Client{Net: "tcp", Timeout: 8 * time.Second}).ExchangeContext(queryCtx, q, address)
	e.mu.Lock()
	retired := sharedAddress == "" && selected.retired
	e.mu.Unlock()
	if err != nil || retired {
		return fail()
	}
	return answer
}

func (e *engine) serveDNSTCP(ctx context.Context, conn net.Conn) error {
	d := &dns.Conn{Conn: conn}
	for i := 0; i < 32; i++ {
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		q, err := d.ReadMsg()
		if err != nil {
			return err
		}
		if err = d.WriteMsg(e.dnsQuery(ctx, q)); err != nil {
			return err
		}
	}
	return nil
}

func (e *engine) serveDNSUDP(ctx context.Context, conn N.PacketConn, destination M.Socksaddr) error {
	for {
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		b := buf.NewSize(65535)
		_, err := conn.ReadPacket(b)
		if err != nil {
			b.Release()
			return err
		}
		q := new(dns.Msg)
		err = q.Unpack(b.Bytes())
		b.Release()
		if err != nil {
			return err
		}
		answer := e.dnsQuery(ctx, q)
		limit := 512
		if edns := q.IsEdns0(); edns != nil {
			limit = max(512, min(4096, int(edns.UDPSize())))
		}
		answer.Truncate(limit)
		data, err := answer.Pack()
		if err != nil {
			return err
		}
		if err = conn.WritePacket(buf.As(data), destination); err != nil {
			return err
		}
	}
}

func (e *engine) Close() error {
	e.once.Do(func() {
		e.closeErr = errors.Join(e.closeErr, e.beginDrain())
		for _, session := range e.sessions {
			e.closeErr = errors.Join(e.closeErr, session.rules.Disable())
		}
		e.cancel()
		if e.original != nil {
			e.closeErr = errors.Join(e.closeErr, e.original.Close())
		}
		e.mu.Lock()
		for id, app := range e.apps {
			app.cancel()
			windows.CloseHandle(app.job)
			delete(e.apps, id)
		}
		e.mu.Unlock()
		for _, session := range e.sessions {
			e.closeErr = errors.Join(e.closeErr, callUndo(session.undoAlias))
		}
		if e.tun != nil {
			e.closeErr = errors.Join(e.closeErr, e.tun.Close())
		}
		if e.stack != nil {
			e.closeErr = errors.Join(e.closeErr, e.stack.Close())
		}
	})
	return e.closeErr
}

func (e *engine) beginDrain() error {
	e.drainOnce.Do(func() {
		e.mu.Lock()
		for id, app := range e.apps {
			app.cancel()
			windows.CloseHandle(app.job)
			delete(e.apps, id)
		}
		e.mu.Unlock()
		for id := range e.sessions {
			e.drainErr = errors.Join(e.drainErr, e.unregister(id))
		}
	})
	return e.drainErr
}

func (e *engine) drain() error {
	err := e.beginDrain()
	e.mu.Lock()
	deadline := time.Now()
	for _, session := range e.sessions {
		for _, entry := range session.mappings {
			if entry.expires.After(deadline) {
				deadline = entry.expires
			}
		}
	}
	e.mu.Unlock()
	if wait := time.Until(deadline); wait > 0 {
		timer := time.NewTimer(min(wait, 61*time.Second))
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-e.ctx.Done():
		}
	}
	return err
}

var _ tun.Handler = (*engine)(nil)

// Network changes can create a more specific route that silently bypasses
// capture. Do not continue showing the application as captured in that case.
func (e *engine) checkNetwork() error {
	if e.ctx.Err() != nil {
		return errors.New("Windows 流量捕获已停止")
	}
	// Failed cleanup stays owned. Retry on the next heartbeat even if the
	// DNS lease keeps an idle helper alive until VPN disconnect.
	for _, session := range e.sessions {
		if !session.rules.active && len(session.rules.undo) > 0 {
			if err := session.rules.Disable(); err != nil {
				return fmt.Errorf("软件接管规则清理未完成：%w", err)
			}
		}
	}
	if err := e.reapRetiredPools(time.Now()); err != nil {
		return fmt.Errorf("移除已退役的 DNS 映射池：%w", err)
	}
	if domains := e.dnsPolicy.domains("", nil); len(domains) > 0 && time.Since(e.lastDNSCheck) >= 30*time.Second {
		if err := checkNRPTActive(e.ctx, e.id, domains, e.dnsAddress.String()); err != nil {
			return err
		}
		e.lastDNSCheck = time.Now()
	}
	routes, err := routeRows()
	if err != nil {
		return err
	}
	var wanted []netip.Prefix
	for _, session := range e.sessions {
		wanted = append(wanted, session.aliases)
		if session.rules.active {
			wanted = append(wanted, session.resources...)
		}
	}
	for _, resource := range wanted {
		found := false
		for _, r := range routes {
			if r.Interface == e.index {
				if r.Prefix == resource {
					found = true
				}
			} else if r.Prefix.Bits() >= resource.Bits() && r.Prefix.Overlaps(resource) {
				return errors.New("网络路由发生冲突，软件接管已停止，请使用显式代理或重新连接")
			}
		}
		if !found {
			return errors.New("软件接管路由已被其他网络操作移除，请重新启动项目")
		}
	}
	return nil
}
