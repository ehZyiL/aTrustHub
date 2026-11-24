# 未完成事项（核实版）

分成两类：**A 类只看代码就能判定**（不需要账号/硬件），**B 类必须实机**。
历史记录里大量"待验收"混杂了这两类，导致看起来都卡在用户配合上；这里拆开。

---

## A 类：代码可判定（无 aTrust 账号、无 Windows/Fedora 宿主也能做）

### A1. aTrust 侧安全（需要 aTrust 账号才能做**回归**，但结论是代码事实）

- `third_party/zju-connect/client/atrust/tls.go:28` 与 `auth/auth.go:118` 硬编码 `InsecureSkipVerify: true`。
- `AccessPoint.CertificateSHA256` 只在 EasyConnect 路径生效；aTrust 点写了指纹也被忽略（UI 只对 EasyConnect 提供该输入，但字段本身不设协议限制）。

### A2. 统一入口的访问控制 —— 已修复（B1）

原状：统一入口与每接入点端口都是无认证混合代理，`ListenHost` 只校验非空，改成 `0.0.0.0` 后局域网内出现开放代理。
现状：回环继续免认证（不破坏既有配置），非回环强制用户名/口令；SOCKS5 走用户名口令、HTTP 走 407，
SOCKS4 在需认证的监听上直接拒绝；非回环无口令的旧配置在加载时回落 `127.0.0.1` 并告警。
详见 [design/networking.md](design/networking.md) §2.1。

### A3. 系统代理的生命周期（Windows）—— 已修复（B2）

原状：不保存用户原有 `ProxyServer`；`recoverResourceProxy` 依赖 `Aggregate().Addr`；退出失败无留痕；`sysProxyOn` 判定早于恢复。
现状：系统代理写入带事务日志（Before/Installed，0600，先落盘再改注册表），关闭/退出/崩溃后三态恢复；
恢复不再依赖监听状态且先于所有权判定执行；写入后拉起轻量 watchdog 子进程，硬杀也能恢复。
记录被第三方占用或损坏时不会形成死锁：显式重新接管会把当前值记为新的 Before，`off` 也不会去关闭别人的代理。
详见 [design/recovery.md](design/recovery.md) 第 6 节。

另：已修复“改端口后系统代理指向旧端口”的断网分支——`releaseLostSystemProxy` 现在区分
“自己上次写的地址” 与 “第三方改写”，前者重新指向新入口而不是放弃管理。

### A4. 应用开关（`DisabledApps`）—— 已修复（B3）

原状：`workeripc.Config` 无该字段，`resourceCaptureConfigs` 不过滤 → EasyConnect 与应用接管两条路径开关无效；
toast 却声称会生效。
现状：worker 协议 **v7** 的 `IPRule`/`DomainRule` 带上 `AppId`（附加字段），Hub 在 `endpoint.publishResourcesLocked`
单点过滤（`filterDisabledAppsSnapshot`），无归属的规则保守保留；开关改动在 `Manager.Apply` 里即时重发快照，
**无需重登**；映射身份的 `Version` 仍取自未过滤快照，避免 DNS 池被误判为换绑。
已建立的连接不被打断，只影响新决策。

### A5. 统一入口端口回退 —— 已修复（B2）

端口被占时不再静默换端口：单次绑定失败即写 `aggregateErr` 并在界面显示，提示换端口。
随之一并修掉「改端口后系统代理指向旧端口」的断网分支（`releaseLostSystemProxy` 区分自己的旧地址与第三方）。

### A6. IPC 协议单源化 —— 已修复（B5）

`internal/workeripc/cmd/protogen` 是唯一生成器：`go generate ./internal/workeripc` 从 worker 仓库复制并重写包名，
`-check` 模式代替了两处 `sed + diff`，并接进两个打包脚本与 CI。协议现为 **v7**（规则带 `AppId`）。

### A7. 后台 goroutine 的数据竞争 —— 已修复（B4）

后台只读 `configForBackground()`（`cfgMu` 加锁后返回深拷贝）；`tunOn/tunPending/sysProxyOn/sysProxySwitch/
tunWanted/quitRequested/tunPID` 全部改为 atomic；删掉了 `tunOnA/tunPendingA` 双写镜像。
验证：Windows 侧靠锁/原子语义与并发写入冒烟测试；`-race` 在 WSL Debian（有 gcc）跑通，Hub 全模块无 DATA RACE。

### A8. 三套 TUN 实现并存

| 实现 | 服务对象 | 现状 |
|---|---|---|
| `zju-connect-multitun`（`globaltun.go`） | 仅 aTrust，文件控制通道 | Windows/macOS 可用，Linux 无 |
| `internal/wincapture`（应用接管） | 全部在线网关 | Windows |
| `internal/capture`（应用接管） | 全部在线网关 | Linux |

`Manager.SetTunServed` 只服务第一套；代码注释已写明"新 worker 系统 TUN 不得使用它"。

### A9. e2e 与测试基线 —— 部分修复（B5）

`tests/e2e` 模块已建立并重新加入 `go.work`：黑盒驱动真实 worker，覆盖无效配置拒绝、版本不匹配拒绝、
未知消息类型拒绝（不需要网关/网络）。Hub 侧的跨包场景仍主要由 `internal/vpn` 的集成测试承担。
`-race` 已在 WSL Debian（有 gcc）跑通：Hub 全模块 + tests/e2e 均无 DATA RACE。
- 3 个 Windows 普通用户进程测试在管理员令牌下必失败，需普通桌面令牌执行。
- `go test -race` 需要 CGO/gcc，固定环境里未跑。

### A10. 仓库形态

- `easy-connect/` 根目录（`go.work`、`docs/`、`README.md`）不在任何 git 仓库内。
- 两个内核真源（`aTrustHub/third_party/zju-connect` 与 `zju-connect/`）并存且已漂移。
- 两个 `go.work`（根 + `aTrustHub/go.work` 的 `use .`）导致"从哪个目录构建"决定依赖版本。

---

## B 类：必须实机（用户配合）

### B1. Windows

| 项目 | 需要 |
|---|---|
| 普通权限桌面跑 `test-capture.ps1`（含新装/更新/混装拒绝/移除） | 普通令牌桌面会话 |
| UAC 接受与拒绝、助手崩溃后恢复 | 交互桌面 |
| 双网关隔离 + 第三方 TUN 两种启动顺序 | 两个可登录网关 + 自有 TUN |
| 待机 / S4 唤醒后状态恢复 | 电源事件 |
| NRPT 实际命中、域名接管 | 授权内网域名（当前只有 IP 资源样例） |

### B2. Fedora / Linux

| 项目 | 需要 |
|---|---|
| 安装/升级/卸载 **v10** 助手（systemd、真实 systemctl） | root 授权 |
| SELinux Enforcing、firewalld、Tailscale 共存 | 实机宿主 |
| systemd-resolved 真实分域接管 | Fedora 宿主（Debian 用例已过，但宿主不同） |
| T16b 同池模式往返（软件接管 ↔ 系统 TUN 不重登） | 实机 + 真实网关 |
| 映射池跨模式复用后的缓存/TTL 行为 | 实机 |

### B3. 协议能力（依赖网关）

| 项目 | 需要 |
|---|---|
| 业务 IPv4 UDP 端到端 | 两个 L3 网关 + 已授权 UDP 服务 |
| IPv6 | 网关确需下发 IPv6 租约；当前代码路径明确拒绝，`client/easyconnect` 只取 IPv4 租约 |
| DNS 离线备用（同业务组 `dnsFailover`） | 两网关提供同名服务 |
| 域名授权资源（非 IP） | 授权内网域名样例 |

### B4. 性能

`scripts/measure-tun-performance.py` 的采集链路已在 Windows 与 WSL Debian 回环验证；
真实对照（专用 SOCKS 端口 vs 系统 TUN，同网关同负载）未做。

---

## 局域网分享（T01–T10 已实现，复审 10 项已修复，实机验收未做）

已落地：模型/口令/严格出口/服务与控制器/B 端会话/历史缓存/UI/诊断/Windows 规则工具。
细节与证据见 [design/lan-relay-sharing-implementation-2026-11-24.md](design/lan-relay-sharing-implementation-2026-11-24.md) §16。

复审（`e888e47`）提出的 S1–S3、R1–R7 已逐项修复并有回归：后台不再写 UI 配置（race 干净）、
防火墙改走已提权助手并覆盖完整生命周期、会话结束与资源更新同循环监听、历史并集持久化、
资源代次与租约撤销、终止错误保留类型、重连重置更新序号。逐项证据见该校验文档 §17。
Windows 防火墙的运行时行为（提权接受/取消、中文/空格路径、崩溃恢复）仍需实机验收。

只能在实机上判定、因此仍列未完成：

| 项目 | 判定方式 |
|---|---|
| 跨机互联（Win↔Win、Win↔macOS、Linux↔Win/macOS） | 发行包实际互连，不用交叉编译代替 |
| Windows 防火墙最小规则 | 提权、读回、拒绝授权、崩溃后 journal 清理 |
| 规模与长连接 | 5–10 客户端、持续下载、CPU/内存/句柄/goroutine |
| 弱网/休眠/换网段/VPN 重登 | 分享代次与租约是否按契约收敛 |
| 工具覆盖 | 浏览器、Git HTTPS、curl、SSH/数据库逐项记录 |
| §13 默认值校准 | 由上面几项反推，不先写成"已验证" |

代码可判定、但本次有意未做：

| 项目 | 原因 |
|---|---|
| 二维码渲染 | 口令文本已是唯一载荷，复制可用；渲染未接 |
| 「更换口令并断开现有连接」 | 按钮存在但禁用，避免提供未验证入口；关闭再开启即可换身份 |
| 剪贴板自动识别 | 模型字段与默认关闭语义已就位，读取回调未接（未开启时绝不读） |
| 资源变化的精细化断流 | 目前保守关闭该分享的全部业务流（按代次整体淘汰，不做逐条比对） |
| macOS/Linux 自动防火墙 | 只有指引，不做统一"一键修复" |

---

## 附：自动化验证矩阵（本轮已在 WSL Debian 跑通）

在 WSL Debian（go 1.27.3 linux/amd64、gcc 可用、16 核）跑通：

| 门禁 | 结果 |
|---|---|
| `go vet ./...` | 通过 |
| `go test ./... -count=1` | 17 个包全绿（含只在 Linux 编译的 `internal/capture`、`internal/resolved`） |
| `go test -race ./... -count=1` | 全绿，无 DATA RACE（根包 36s、`internal/vpn` 17s） |
| worker（`GOWORK=off`）desktop/resolve/dial | 全绿 |
| worker v7 探针 | 无效配置→status 1 + 带 version 的 error 帧；版本 6/8、未知类型→status 1 且无输出 |
| `tests/e2e`（含 `-race`） | 全绿 |
| `scripts/test-helper-setup-linux.sh` | 10 项隔离用例全 PASS（含"旧候选协议在停旧服务前被拒绝"）；宿主 systemd 服务保持未安装 |
| 两个打包脚本 `bash -n` | 通过 |

Linux 侧顺带修掉一个真实缺陷：`resource_proxy_linux.go` / `resource_proxy_stub.go` 的 `recoverResourceProxy`
仍是旧的 2 参数签名，导致 **Linux（和 darwin）根本无法编译**——Windows 侧因为文件带 `!windows` 构建标签从未暴露。

## C. 已确认完成、不应再列为"未完成"

| 项目 | 证据 |
|---|---|
| worker IPC v7 + `strict_vpn` / `flow_prepare` / `flow_cancel` | `internal/workeripc/protocol.go`，`processSession.configureReady` 校验能力组合 |
| Windows helper v7 / Linux helper v11，两侧都拒绝混装 | 常量 + 打包脚本 `--protocol-version` 自检 + 安装脚本候选校验 |
| 独立 `internal/routing` 决策层（归属/授权/策略/预算） | `Decide` / `DecideDNS` / `applyPolicy` |
| 不可变资源快照 + 代次隔离 | `Manager.routeSnapshot` / `currentRoute` 的 gen+endpoint+sess 三元校验 |
| 合成地址映射池（Session 绑定、不可改绑、TTL/容量/退役） | `internal/dnsmapping/pool.go` |
| 打包链路：staging 目录 + SHA256 清单 + 协议自检 + 旧文件哨兵 | `scripts/package-{windows,linux}.sh` |
| Linux 安装/卸载 10 项隔离用例 | `scripts/test-helper-setup-linux.sh` |
| 非回环监听强制认证（SOCKS5 用户名口令 / HTTP 407 / 拒 SOCKS4 / 凭据不转发） | `internal/proxy`、`Manager.settingsProxyAuth`、`Settings.AuthRequired` |
| 凭据库不可用不再静默丢密码 | `store.ErrSecretNotPersisted` + 编辑器提示 |
| 转发不再丢掉握手期已缓冲的字节（CONNECT/SOCKS5 管道化请求） | `proxy.bufferedConn` + `relay_test.go`（变异测试已验证：去掉修复即失败） |
| 后台 ticker 可停止（不再用 `time.Tick`） | `tickersStop` + `state_ticker.go` / `app.start()` 的 `maintainState` 循环 |
