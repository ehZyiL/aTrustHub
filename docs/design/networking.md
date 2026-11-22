# 网络接管、路由与 DNS（核实版）

## 1. 四种接管方式与互斥关系

顶栏胶囊的下拉是唯一入口，四档互斥（`view.go`）：

| 档位 | 常量 | 判定 |
|---|---|---|
| 不使用 | `captureOff` | 仅本机代理端口，不改系统 |
| 系统代理 | `captureSystem` | `sysProxyOn` |
| 全局 TUN | `captureGlobalTUN` | `tunOn \|\| tunPending`（**只服务 aTrust 会话**） |
| 应用接管 | `captureAppCapture` | `resourceTUN` 处于 Running/Busy/CleanupPending |

当前生效值由 `app.captureMode()` 按 **应用接管 → 全局 TUN → 系统代理 → 不使用** 的顺序反查，
所以它读的是**实际状态**而不是用户点选的意图；切换是异步的，界面每帧回读。

档位出现的条件分两层（`captureSupported` / `captureReady`）：

- **平台/配置做不到 → 直接隐藏**（原因写进运行日志，去重）
- **做得到但此刻没条件 → 仍列出，点击时才拒绝**（`captureBlocker` 给出具体理由）

## 2. 各方式的实现落点

### 2.1 不使用：本机代理端口

- 每接入点一个混合端口：SOCKS5 **与** SOCKS4 **与** HTTP(CONNECT + absolute-URI) 复用同一监听（`internal/proxy`）。
- 统一入口（默认 1080）在同一端口提供同样三种协议。
- **监听地址决定是否认证**（`model.IsLoopbackHost` / `Settings.AuthRequired`）：
  - 回环（`127.0.0.1`、`::1`、`localhost`）→ 不认证，保持既有用户配置不变；SOCKS4 仍可用。
  - 非回环 → 必须带用户名/口令（`Settings.ProxyAuth`）：SOCKS5 走 RFC1929 用户名/口令，HTTP 走 `Proxy-Authorization: Basic` + 407；
    SOCKS4 因协议本身无认证字段而**直接拒绝**；`Proxy-Authorization` 不转发给目标站点。
  - 口令在 `Settings.Validate` 里强制（非回环且为空/少于 12 位直接拒绝），保存时自动生成 24 位（`model.NewProxyPassword`）；
    加载到“非回环但没有口令”的旧配置时回落 `127.0.0.1` 并在启动日志与提示里说明。
- **只支持 TCP**：SOCKS5 的 `UDP ASSOCIATE` 明确返回 "command not supported"；UDP 只能走私有的、要求认证的数据报通道（见 §4.5）。
- worker 侧的私有 SOCKS 端口使用每次登录随机生成的用户/口令，只经继承的 stdio 之外的私有通道使用，不暴露给用户。

### 2.2 系统代理

- Windows：写 `HKCU\...\Internet Settings`，`ProxyServer = socks=127.0.0.1:<port>`、`ProxyOverride = <local>`、`ProxyEnable = 1`，再用 `InternetSetOption` 通知（通过 PowerShell 调 wininet）。
  - **事务日志**：写入前先把 `Before`（用户原值）与 `Installed` 存进 `<数据目录>/system-proxy-recovery.json`（0600），关闭/退出/崩溃后按三态恢复（见 [recovery.md](recovery.md) §6）。
  - **watchdog**：写入成功后拉一个轻量子进程（`--proxy-watchdog <pid> <dir>`），用进程句柄等 GUI，被 kill 也能恢复——仅 Windows，不需提权。
- macOS：`networksetup` 设置 SOCKS/HTTP/HTTPS 代理（**无 journal**：逐服务读回与恢复尚未在实机验证）。
- Linux：**不提供**（`applySystemProxy` 直接返回 `errLinuxHelperUnavailable`）。
- 守护：`guardSystemProxy` 每 3 秒探活统一入口；入口不再监听就自动关掉系统代理，避免整机断网。
- 归属：Windows 上 `systemProxyOwned` 会比对 `ProxyServer` 是否仍是自己写的值；被第三方改写则放弃管理（`releaseLostSystemProxy`）。
  如果注册表里的地址仍是自己“上一次配置”写入的（改过端口），不是第三方，而是重指向新入口。

### 2.3 全局 TUN（旧，仅 aTrust）

- 组件：打包在 `resources/` 的 `zju-connect-multitun`（Windows `.exe`）。
- 会话来源：**读 GUI 落盘的 aTrust 会话文件**（`atrust/<id>.json` + `.resource.json`），不重新登录。
- 控制通道：**文件**——`tun-config.json`(0600)、`tun.pid`、`tun.stop`、`tun.reload`、`tun.probe(.result)`、`gui.alive`(GUI 心跳，helper 据此自退)。
- 提权：Windows 用计划任务 `aTrustHubTUN`（首次一次 UAC，之后免提示）；macOS 用 `/etc/sudoers.d/atrust-hub` 免密规则。
- 每个接入点分到一段 fake-IP：`tunFakeRanges` = 198.18.0.0/17 … 198.21.128.0/17（最多 8 个点）。
- 启动后 `Manager.SetTunServed(ids)` 会把 GUI 自己的会话交给 helper 并关闭（同一 aTrust 会话只能有一条隧道）。
- 启动/运行期的 DNS 自检：`helperAnswersDNS` 连续失败 3 次会**自动关闭 TUN** 以恢复系统网络。

### 2.4 应用接管（新，worker 驱动）

链路：`resourceTUNController` → `localapps.Manager.StartSystemCapture` → 平台实现 → `Manager.DialCaptured`。

- `resourceCaptureConfigs()` 从在线网关的资源快照生成 `CaptureConfig`（域名、网段、DNS 发布/确认回调、映射池前缀）。
  资源快照已经是“应用停用开关生效后”的视图（`endpoint.publishResourcesLocked`），所以应用接管与聚合代理看到同一份授权。
  一个网关不可接管（旧核心/会话已结束/资源解析失败）只会被跳过并在状态行报明原因，不会让其余网关一起失败（`partialCaptureError`）。
- 启动顺序：**先起系统捕获 → 再暂停本应用自己的系统代理**（`suspendProxyForResourceTUN`，保留第三方代理不动）；失败按逆序回滚。
- 每 2 秒 `Reconcile(ctx, configs)`：网关资源变化、上下线都在这里增量更新，不需要重启整个接管。
- 平台实现：Windows 走 `internal/wincapture`（Wintun + gVisor + NRPT + 路由 + 恢复进程）；Linux 走 `internal/capture`（cgroup v2 + nftables TPROXY + systemd-resolved 域名所有权）。
- 与旧全局 TUN **互斥**：`startGlobalTUN` 先检查 `resourceTUNActive()`，反之亦然。
- 注意：`Manager.SetTunServed` 只给旧 aTrust TUN 用；新的 worker 系统 TUN 走 `DialCaptured`，不走会话移交。

## 3. 路由决策（`internal/routing`）

`Decide()` 是纯函数：**不解析 DNS、不拨号、不分配资源**。顺序固定：

1. `ParseRequest`：目标必须是 `host:port`，端口 1–65535，协议归一（tcp4→tcp，udp4→udp）。
2. 目标落在合成地址块 `198.19.0.0/16` 但没带映射身份 → 直接拒绝（"合成地址缺少有效的会话映射身份"）。
3. **用户策略优先**（`applyPolicy`，按保存顺序取第一条匹配）：`block` / `direct` / `gateway`。`direct` 对合成地址无效；`gateway` 与入口绑定冲突时拒绝。
4. 带映射身份的请求：必须命中同一次会话的网关，且该网关 `Online && Strict`（UDP 还要 `UDP` 能力），否则拒绝。
5. 归属计算（`claim`）：`Current` 快照 + `Known`（退役快照，**只用于归属，不授权**），取最高具体度。
6. 多个网关同时归属 → 除非命中显式"同业务出口"组（`SharedExits`），否则报冲突，不猜测、不随机试探。
7. 内网 IPv6 → 拒绝（"内网 IPv6 尚不支持"）；非 tcp/udp → 拒绝。
8. 逐个候选校验：网关在线、端口/协议**已授权**、具备严格拨号能力（`Strict`）、UDP 已协商。
9. 输出 `vpn` + 候选集，或 `direct`（目标不属于任何受管资源）。

`claim()` 的关键不变量：**DNS 声明永不授予端口权限**。

- 命中 `IPRules` 且端口/协议合法 → `allow = true`
- 命中 `DomainRules` 且端口/协议合法 → `allow = true`
- 命中 `InternalDomains` 或 `StaticDNS` → 只给 `score`（`dnsOnly`），`allow` 保持 false，最终仍需 worker 对解析结果再校验

`Dial` 侧还有一层：`dialRoute` 先 `routing.Decide`，再按 `settings.Routing`（延迟/轮询/故障转移/按域名固定）在**已授权的候选集内**选出口；`按域名固定` 用基于稳定网关 ID 的 rendezvous hash（`routing.Rendezvous`），不是索引取模。总预算 15 s、单次 5 s（可配）。

## 4. DNS

### 4.1 两种角色

- **split DNS 入口**（`internal/splitdns`）：本机回环 UDP/TCP 监听，供接管模式下的解析器使用；带并发上限、UDP 截断转 TCP、会话取消。
- **本机 DNS 服务**（worker/aTrust 会话内 `service.NewDnsServer`）：走隧道向网关 DNS 查询。

### 4.2 DNS 归属（`routing.DecideDNS`）

- 先看显式 `DNSBindings`（域名 → 网关），无绑定再按资源归属。
- 多个归属时同样要求显式"名称服务等价"组（`SharedExits` 的 `DNSFailover`），且只在新查询时按组内顺序选在线且仍声明该名称的网关。
- DNS 没有业务端口，所以 `claim(..., port=0, "dns")` 只用来算归属分，不产生授权。
- 同一域名在 A/B 代表不同业务时，首版要求指定默认归属；靠 DNS 自动按端口分流做不到（系统解析器看不到业务端口）。

### 4.3 合成地址映射（`internal/dnsmapping`）

用于"只有域名授权"的资源：透明 TCP 只保留目的 IP，无法区分共享 IP 上的多个域名。

| 约束 | 值 | 出处 |
|---|---|---|
| 合成地址块 | `198.19.0.0/16`（上游 resolver 自用 `198.18.0.0/16`，两者不得重叠） | `workeripc.CaptureAliasBlock` |
| 前缀粒度 | `/20` – `/24`，必须已对齐 | `dnsmapping.ValidPrefix` |
| 默认分配 | `198.19.<i*16>.0/20`，i = 0..15 | `dnsmapping.Choose` |
| 单会话 TTL 上限 | 1 – 60 秒 | `Stage` |
| 单次发布条目 | ≤ 32 | `Stage` |
| 单池条目上限 | 8192 | `Stage` |
| 现实地址校验 | 必须 IPv4 全局单播，排除回环/链路本地/`198.18.0.0/15` | `Stage` |

生命周期：`Begin`（在途引用计数）→ `Stage`（记账，未发布）→ `Confirm`（平台装好后才 published）→ `Acquire`（业务连接，引用计数 +1）→ `Retire` + `prune`（在途=0、streams=0、条目全过期才真正回收）。

不变量：**池一旦绑定某会话代次就不能改绑**；已发布地址不能改指向另一个域名或真实 IP；未确认或已过期的地址拒绝 `Acquire`。

### 4.4 系统侧 DNS 策略

- Windows：NRPT（`dnsPolicy` 把当前所有 scope 的后缀并集写进一条自有规则），安装/清理都按精确命名空间核对，外部改动保留并报错。
- Linux：`systemd-resolved` 的 route-only domain，绑在本应用自有的 dummy link 上；先 `ListDelegates` 检查是否已有冲突委托（旧 resolved 报 `Unknown method` 视为无委托）。

### 4.5 业务 UDP

- 只有 **IPv4 L3 会话**且 worker 在 `ready` 里公布 `strict_udp_ready` 时才启用。
- Hub 必须**同时**收到私有就绪信号与同一请求的 VPN 授权结果，才算成功；`UDP 捕获走 direct` 一律改判 `blocked`。
- 数据路径是私有的、带认证的 SOCKS 数据报通道（0xf5 前导 + 用户名/口令 + 长度前缀帧），不是标准 UDP ASSOCIATE。
- DNS 的 UDP 单独走各平台的 DNS 链路，不受此影响。

## 5. 范围边界（已核实）

| 项 | 现状 |
|---|---|
| IPv4 TCP | 基线能力，四种方式都覆盖 |
| 业务 IPv4 UDP | 试验能力，仅 L3 + 能力协商；公开代理端口不支持 |
| 内网 IPv6 | **明确拒绝**（`Decide` 直接返回"内网 IPv6 尚不支持"）；worker 保留 IPv6 资源归属供 Hub 判断 |
| 公网 IPv6 | 保留原路径，不接管 |
| ICMP | 不转发：包栈只把 TCP/UDP 交给 handler（`packetstack/stack.go` 注释明确写"local ICMP echo 会造成假健康"） |
| 默认路由接管 | 不安装 `0.0.0.0/0`；只注入资源网段 |
| 捕获地址总量 | 单次接管上限 1048576 个 IPv4 地址（`netpolicy`） |
| 已建立连接 | 切换/重连不迁移，只对新连接生效 |
