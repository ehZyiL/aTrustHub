# 局域网分享：自动发现（已实现）

状态：已实现并通过自动化验收；跨机与平台权限仍需实机覆盖（见 §9）。日期：2026-11-24。

2026-11-26 生命周期更新：构造不启动任务，发布按需启停，浏览关闭等待退出；当前证据见 [P1 记录](../plans/p1-lifecycle-2026-11-26.md)。下文复审表保留当时的历史处理结果。

本文件记录**当前代码实际怎么工作**，与 §9 未验证项分开写。需求与分派计划在仓库外
`easy-connect/docs/lan-relay-discovery-implementation-plan-2026-11-24.md`。

## 1. 范围

一期只做「打开页面 → 发现已开启的分享 → 首次粘贴口令加入 / 已导入节点点击连接」。

发现负责**定位**，始终不负责**授权**：广播里没有 token、没有证书指纹、没有 VPN 资源。
加入仍然只走现有分享口令 + 固定证书校验。

刻意不做：全网段扫描、自定义 UDP 备用协议、跨网段目录、自动改写已保存节点地址、
免口令配对、IPv6 分享、逐资源共享、自动开启共享/VPN/系统代理/防火墙放行。

## 2. 后端选型（D0）

| 项 | 决定 | 理由 |
|---|---|---|
| 编解码 | `github.com/miekg/dns`（已在依赖内） | 纯 Go、无 CGO，完整支持 TXT/SRV/PTR/A、名称压缩、大小写规则 |
| 传输 | 自建 socket：每网卡一个 `224.0.0.251:5353` 组播套接字（`net.ListenMulticastUDP`，套接字选项经 `golang.org/x/sys`） | 需要逐网卡收发、TTL 255、回环、goodbye、接收接口归属；`x/net/ipv4` 的控制消息在 Windows 上未实现（§17 W1），改用标准库 socket |
| 新依赖 | 无新增模块；`golang.org/x/sys` 由间接依赖转为直接依赖（逐平台 `IP_MULTICAST_LOOP` / `IP_MULTICAST_TTL`） | 不引入第二个组播库，也不把协议实现改为依赖系统 responder |
| 兼容 | 与系统 responder 共存：`net.ListenMulticastUDP` 带 `SO_REUSEADDR`，逐套接字 `IP_MULTICAST_IF` | Avahi/Bonjour 占用 5353 时仍能收发 |
| 删除语义 | 自己实现 goodbye（TTL 0，连发两次）+ 真实 TTL 过期 | 不依赖第三方库是否把 TTL=0 事件转给应用 |

`internal/relay/discovery.Backend` 是唯一的平台边界；测试用内存 hub 替换它，
因此协议、缓存、发布与浏览生命周期都能确定性测试，不依赖真实组播。

## 3. 协议 v1

| 记录 | 内容 |
|---|---|
| 服务类型 | `_connecthub._tcp.local.`（`discovery.ServiceType`） |
| 实例名 | `CH-<完整ShareID>._connecthub._tcp.local.` |
| SRV | 目标 `ch-<shareid>.local.`，端口=实际绑定端口 |
| A | 目标名的当前业务监听 IPv4（仅 RFC1918） |
| TXT | `dv`=1、`pv`=分享协议版本、`sid`=完整分享 ID、`name`=公开名称（可选） |

TTL 按 RFC 6762 §10 分类型：A/SRV 120 秒，PTR/TXT 4500 秒。唯一记录（SRV/TXT/A）带
cache-flush 位。停止时对四类记录各发两次 TTL=0。

### 3.1 名称与 TXT 的边界

- 公开名称：≤40 个 Unicode 字符、≤160 字节、无控制字符、首尾无空白；空值用
  `Connect Hub 分享 <ShareID前6位>`。规则只有一份：`internal/lanname`。
- TXT 总长 ≤1024 字节、≤16 个逻辑字段、键不重复、单字段 ≤255 字节（编码后）。
- 值过长时 multicast DNS 会把一个值拆成多个 character-string；解析时按 RFC 6763 §6.4
  把不含 `=` 的片段接回上一个值，再还原 `\DDD` 转义。中文名称因此能原样往返
  （`TestWireRoundTripsALongChineseName`）。
- 未知键在限额内忽略；缺 `dv`/`pv`/`sid`、`dv`/`pv` 非数字、`sid` 不是 22 字符 base64url
  一律拒绝整条记录。

### 3.2 接收限制

- 只接受 RFC1918 IPv4；公网、IPv6、坏地址直接丢弃，不产生候选。
- 只接受端口 1–65535。
- 只接受本服务类型下的实例名；A 记录必须匹配 SRV 目标名，否则不并入该实例。
- 缓存上限：128 个 endpoint、每实例每网卡 8 个地址；溢出丢弃新条目，不驱逐已知条目。
- 候选身份 = 实例名 + 接收网卡 + IPv4 + 端口；「同一个分享 ID」不是合并依据。

## 4. 模块与文件

| 文件 | 职责 |
|---|---|
| `internal/relay/discovery/types.go` | DTO、限制常量、`Backend`/`Registration`/`Session` 边界、`Announcement.Validate` |
| `internal/relay/discovery/names.go` | 实例名/主机名、TXT 组装与校验、`\DDD` 还原 |
| `internal/relay/discovery/wire.go` | DNS 报文组装/解析、TTL 与 cache-flush、查询构造 |
| `internal/relay/discovery/cache.go` | 记录 → 候选的状态机（分包、乱序、更新、TTL、goodbye）、有界缓存、稳定排序 |
| `internal/relay/discovery/mdns.go` | 真实 socket 后端（发布应答 + 浏览查询）、`link` 抽象 |
| `internal/relay/discovery/publisher.go` | 发布协调器：最新期望、代次校验、迟到注册回收、退避重试、预算内退出 |
| `internal/relay/discovery/browser.go` | 浏览会话、代次、快照推送、关闭回收 |
| `lan_discovery.go` | app 适配：跟随共享状态、UI 页状态、开关/改名/重试、口令加入衔接 |
| `internal/lanname/name.go` | 公开名称规则的唯一实现（model/relay/discovery 共用） |

依赖方向：`lanname` ← `model` ← {`relay`, `discovery`}；`discovery` 不导入 `relay`，
`relay` 不导入 `model`。UI 只读快照。

## 5. 配置与迁移

`model.LANShareSettings` 新增 `DiscoveryEnabled *bool` 与 `DiscoveryName string`，
`relay.Settings` 同步镜像，store 双向映射并复制指针。

- `nil` = 用户从未选择（所有旧配置）。正常运行时不广播；首次「开启共享」表单默认勾选，
  只有用户点「开启共享」才保存。
- `false` / `true` = 明确选择，跨重启保留；`Normalize` 从不改写。
- `Settings.Clone` 深拷贝指针，UI 与后台不共享内存。
- `model.Settings.Normalize` 的「整份配置是否零值」判断改用 `LANShareSettings.IsZero()`：
  否则只带 `discoveryEnabled` 的配置会跳过默认值补全。

## 6. 生命周期

### 6.1 发布条件（唯一实现：`Controller.DiscoverySnapshot` + `app.syncLANDiscovery`）

```text
共享意图 Enabled
且发现偏好显式 true
且 State == Running（服务端已启动、身份/地址/端口已提交）
且地址/端口/网卡有效
```

不满足就撤销。等待（Waiting）、启动中（Starting）、暂停、阻断、关闭、退出都不发布。
公告里的地址与端口来自**实际绑定**，不是请求值。

### 6.2 跟随时机

`Controller` 的通知（`app.lanShareChanged`）合并到一个短期后台任务，读取最新状态后退出。
发现协调器没有常驻 tick；共享已启用时，控制器仍负责监督 VPN 会话。渲染循环、页面是否打开都不参与发布正确性。

### 6.3 发布失败与重试

退避 1/2/5/10/30 秒封顶；离开可发布状态立即取消重试。失败只影响发现：面板显示
「发现不可用，可以使用口令」，共享继续运行，不触发提权、VPN 登录或接口扩大。

### 6.4 退出顺序

撤销公告（有界预算 2 秒）→ 关闭监听 → 其余退出流程。公告撤销失败只记录日志，
远端残留靠 TTL 消失。

### 6.5 状态矩阵（与实现一致）

| 事件 | 发布动作 | 业务动作 |
|---|---|---|
| 首次安装、旧配置恢复 | 无公告 | 不变 |
| 勾选并开启，VPN 未连接 | 等待 | 不替用户登录 |
| 分享进入 Running | 发布实际 endpoint | 不重启分享 |
| VPN/源断开、接口不可用、Blocked | 撤销 | 由原状态机处理 |
| 同一身份恢复 | 发布当前实例 | 身份/端口不变 |
| 关闭发现 | 立即撤销 | token、连接、意图不变 |
| 改名 | 撤回旧公告再发布新的 | 业务身份不变 |
| 关闭共享/删除源/退出 | 取消启动、撤销、回收 | 保持原撤权顺序 |
| 发布失败 | 「发现不可用」+ 有界重试 | 分享继续 |

## 7. 同事端

- 打开「同事分享」默认进入发现页并开始浏览；切到口令页或关闭弹窗、关闭应用即停止。
- 浏览只使用非虚拟的 RFC1918 网卡（默认全部，可手选）；换网/刷新建立新代次，
  旧代次回调丢弃。
- 列表只显示名称、地址、端口、网卡；**不会**因为看到公告就发起连接。
- 「加入」把候选固定下来，切到口令页；口令里的 sid/host/port 必须与候选一致，
  不一致则拒绝并提示，用户可显式改为普通导入。
- 已导入节点按分享 ID 匹配：endpoint 相同显示「已导入，待验证」并提供「连接」（只连
  本地保存的地址）；endpoint 不同显示「地址不同，需新口令核对」，不自动改写。
- 任何发现结果都不写 `Current`/`Known`、不触碰历史保护门控、不设置 AutoConnect、
  不切换系统代理。

## 8. 自动化验收

命令：

```sh
go test ./...
go test -race ./...
go vet ./...
go build ./...
env GOOS=windows GOARCH=amd64 go build ./...
env GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build ./...
```

关键用例（按验收矩阵编号）：

| 编号 | 用例 |
|---|---|
| A1/A5/A7 | `model/discovery_test.go`：三态、Clone 深拷贝、名称规则、零值补全 |
| A2 | `lan_discovery_test.go` `TestAcceptanceUpgradeDoesNotAnnounce` |
| A3/A4 | `TestAcceptanceEnableFormSavesTheChoice`、`controller_test.go` 相关 |
| A6 | `TestAcceptanceFailedSaveSemantics`、`TestSetDiscoveryRollsBackWhenTheSaveFails` |
| B8/B10 | `TestAcceptanceOnlyRunningAnnounces`、`TestDiscoverySnapshotNeedsChoiceAndRunning` |
| B11 | `TestAcceptanceStoppingDiscoveryKeepsTheShare`、`TestDisableKeepsTheDiscoveryPreference` |
| B12/B13 | `TestPublisherDropsALateRegistration`、`TestPublisherRenameDuringRegistration` |
| B8/B10（端到端） | `TestAcceptanceWaitingShareAnnouncesWhenItStarts`、`TestAcceptanceShutdownWithdrawsTheAnnouncement` |
| B14/B15 | `TestPublisherRetriesAndStopsWhenCleared`、`TestPublisherCloseRespectsItsBudget` |
| C16/C17/C18 | `TestCandidateNeedsEveryRecord`、`TestCandidateGoesAwayOnGoodbyeAndExpiry`、`TestUnusableRecordsAreRefused`、`TestSameInstanceOnTwoInterfaces` |
| C19/C20 | `TestBrowserCloseWithPacketsInFlight`、`TestBrowserCyclesDoNotLeak` |
| C21 | `TestAcceptanceBrowsingNeverDials` |
| D22/D23/D26 | `TestAcceptanceCandidateMismatchIsRefused`、`TestAcceptanceDiscoveryDoesNotTouchSavedNodes` |
| D27/E30 | `TestAcceptanceDiscoveryFailureDegradesHonestly` |
| E28 | `-race` 全量；浏览器只交付不可变快照 |
| E29 | `TestAcceptanceMacPackageDeclaresDiscovery` |
| 协议/线格式 | `TestWireRoundTrip`、`TestWireRoundTripsALongChineseName`、`TestWireIgnoresForeignTraffic` |
| 真实组播 | `TestLiveMulticastRoundTrip`（无网卡或短模式自动跳过） |

真实组播用例在本机实际跑通：发布 → 发现 → goodbye → 移除，全部走真实 UDP 组播。

本机实测（20 轮，接口 `enp1s0`，`TestLiveDiscoveryLatency`）：

```text
首次发现时延：min=268µs  median=463µs  p95=938µs  max=938µs
```

这是同机回环组播的数字，只说明协议与事件链路本身的开销；跨机时延还取决于无线环境与
AP 隔离，按 §9 待实机。

端到端链路（`TestLiveDiscoveryJoinEndToEnd`）：A 用生产后端发布并服务，B 用生产后端
发现、用 A 的口令加入，B 的中继会话真实上线（真实 UDP 组播 + 真实 TLS）。

## 9. 未验证（不得当作已支持）

| 项 | 现状 | 需要的证据 |
|---|---|---|
| Windows/macOS 实机发现 | Windows/Linux 都已实机跑过**同机回环**组播（发布→发现→goodbye→移除）；macOS 未测；**跨机**未测 | 两台真机、实际发布包、系统防火墙默认配置下的收发 |
| macOS 15 本地网络权限 | 已在 `scripts/package-mac.sh` 写入 `NSLocalNetworkUsageDescription` + `NSBonjourServices` | 允许/拒绝/恢复，拒绝后业务 TCP 的表现 |
| Windows 纯 Go 后端入站 5353 | 未实测。已确认：程序只创建 **TCP** 入站规则（`internal/relay/firewall_script.go` 的 `Protocol = 'TCP'`），5353/UDP 没有任何放行；提权 helper 的安全不变式是「本程序 + 专用配置文件 + RFC1918 对端 + 单端口 TCP」（`ValidateHelperOperation`），因此**加一条 UDP 规则不是加一行代码**，要同时改 `FirewallRule` 结构、脚本与校验策略。界面已给出可诊断的提示（§19 R9-1）。同机回环组播（`IP_MULTICAST_LOOP=1`）不经过接口入站过滤，**不能**用来证明放行 | 普通用户、无放行规则下的收发记录；专用/公用配置文件 × 网络发现开/关 |
| 与系统 responder 共存 | 代码使用复用地址 + 逐网卡组播接口 | Avahi/Bonjour 同时运行时仍能收发的实测 |
| 规模 | 缓存与 goroutine 有上限并有测试 | 同网段 10 主机 ×10 浏览端，30 分钟流量/内存记录 |
| 跨 VLAN / AP 隔离 | 不支持，界面已如实说明 | — |

## 10. 安全边界

- 广播不含 token、完整口令、证书指纹、资源、内网域名、用户名、面板地址、客户端列表。
- 公告只描述本机正在运行、已提交的分享；关闭共享后迟到的注册会立即被撤销。
- 收到的公告只是「线索」：不做 TCP 探测、不读凭据、不写配置；加入必须另有口令。
- 伪造同 sid 的不同 endpoint 不会覆盖已保存节点，也不会获得旧 token。
- 接收侧不解析任意域名、不做 DNS 递归、不接受公网地址。

## 11. 复审记录

### 11.1 第一轮（标准 + 规格覆盖）

| 编号 | 轴 | 问题 | 证据 | 修复 |
| --- | --- | --- | --- | --- |
| R1-1 [P1] | 标准 | `Browser.Close` 之后 `Start` 直接返回，**关闭一次弹窗后再也发现不了** | `TestBrowserReopensAfterClose`（旧行为：重开后收到公告但列表为空） | `Start` 重新打开浏览器；关闭只结束当前浏览会话 |
| R1-2 [P2] | 规格 | `findRelayPointByShareID` 恒返回 `same=true`，「地址不同，需新口令核对」分支不可达，地址不同的分享被显示成可连接 | `TestAcceptanceDiscoveryDoesNotTouchSavedNodes`（断言界面出现「地址不同」且不出现「已导入，待验证」） | 按 sid + endpoint 比较，只有完全一致才复用已保存节点 |
| R1-3 [P2] | 规格 | 公开名称输入框的示例每帧用随机 ID 生成，占位文字闪动 | 代码核对 | 占位改为由当前分享 ID 派生（无 ID 时用固定示例） |
| R1-4 [P3] | 规格 | 保存失败后「重试保存」把公开名称写空 | `TestAcceptanceRetryKeepsThePublicName` | 重试时带当前名称 |
| R1-5 [P3] | 规格 | 空列表在首轮立刻显示「暂未发现分享」，与「5 秒内不判定没有分享」冲突 | `TestAcceptanceFirstSecondsReadAsSearching` | 增加时间窗（默认 5 秒）内的「正在查找局域网分享…」；协调器 2 秒兜底帧保证状态按时切换 |
| R1-6 [nit] | 标准 | `lanDiscoveryUI.pinned/pinnedKey/loadedOnce` 为死字段；`browseInterfaces` 有恒真条件 | 代码核对 | 删除 |

### 11.2 第二轮（并发与安全）

| 编号 | 轴 | 问题 | 证据 | 修复 |
| --- | --- | --- | --- | --- |
| R2-1 [P1] | 标准 | `shutdownLANDiscovery` 二次调用会 `close` 已关闭的 channel 直接 panic；退出后再次打开页面还会重启浏览（套接字已无人回收） | `TestAcceptanceShutdownIsIdempotent` | `stopOnce` + `shutDown` 标记；退出后忽略开启 |
| R2-2 [P2] | 安全 | 浏览器对**每个**收到的 PTR 都补发一次 SRV/TXT 查询，伪造洪泛可以做到「收一包、发一包」 | `TestRepeatedPTRIsQueriedOnce`（去掉守卫时发出 51 个报文） | 每会话按实例去重，上限 256 |
| R2-3 [P2] | 标准 | 过期 ticker 是独立 goroutine，`Close` 之后仍可能推送一次快照到 UI | `TestBrowserDoesNotEmitAfterClose`（去掉守卫时仍推送 1 次） | `publish` 检查关闭状态；顺带删除未等待的 `tickerDone` |
| R2-4 [P3] | 标准 | 后端返回 `(nil, nil)` 时被当成发布成功，面板显示「正在发布」但什么都没注册 | `TestPublisherRejectsANilRegistration` | 视为失败并进入退避 |
| R2-5 [P2] | 规格 | 列表不过滤本机自己的实例（§9.1.5） | `TestAcceptanceOwnShareIsFilteredByAddress` | 仅当 sid 相同**且**地址是本机网卡地址时过滤；同 sid 的远端仍显示 |

### 11.3 第三轮（端到端与验收矩阵）

本轮新增两个真实链路用例，并因此发现一个会让整个同事端失效的缺陷。

| 编号 | 轴 | 问题 | 证据 | 修复 |
| --- | --- | --- | --- | --- |
| R3-1 [P1] | 规格 | `browseInterfaces` 只在「本机也开启过共享」时才枚举网卡，于是**从未分享过的同事端一律显示「没有可用的局域网网卡」**，发现功能对客户端完全不可用 | `TestAcceptanceBrowsingWorksWithoutSharing`；端到端用例先复现「B tab=1、err=没有可用的局域网网卡」 | 网卡列表直接取自本机地址枚举，不再依赖共享控制器 |
| R3-2 | 证据 | 缺少「发现 → 加入 → 真实会话」的链路证据 | 新增 `TestLiveDiscoveryJoinEndToEnd`：A 用生产后端发布并监听真实端口，B 用生产后端浏览、用 A 的口令加入、B 的中继会话真实上线 | — |
| R3-3 [P2] | 规格 | 关闭发现保存失败时只有一行错误，没有 §4 要求的「重试保存」入口 | `TestAcceptanceFailedOffSaveOffersARetry` | 面板显示「偏好没有保存成功…」并提供「重试保存」；重试成功清除提示 |
| R3-4 [P3] | 规格 | 公告未拒绝把 5353 当作分享端口 | `TestAnnouncementRejectsUnusableValues` | 显式拒绝发现端口 |

`TestLiveDiscoveryJoinEndToEnd` 覆盖的链路：

```text
A: Enable(Discovery=true) → Running → Publisher → 真实 UDP 组播
B: 打开发现页 → 真实组播收到 PTR/SRV/TXT/A → 候选出现
B: 固定候选 + 粘贴口令 → sid/host/port 校验 → 写入节点 → 真实 TLS 连接 A 的分享服务
B: mgr.View(point).State == online
```

单机跑通说明：协议、组播收发、候选装配、口令核对、导入事务与真实中继会话能串起来。
它**不**替代两台真机的验收（跨机器、系统防火墙、macOS 权限仍属 §9 的未验证项）。

## 12. 空闲成本（用户不开启时付多少）

以下为 2026-11-26 按需启停后的生命周期。内存对照见 P0/P1 记录；代码与 GUI 的固定成本仍然存在。

| 项 | 空闲（从未开启） | 打开发现页 | 开启共享 + 允许发现 |
| --- | --- | --- | --- |
| 功能专用常驻 goroutine | **0** | 每网卡接收循环、查询循环、缓存过期任务；搜索提示最多存活 5 秒 | 发布协调任务与后端发布循环 |
| 堆 | 仅轻量对象，未启动运行资源 | 受缓存上限约束（128 条），关闭释放快照与缓存 | 运行时公告与注册状态 |
| 文件描述符 | **0**（空闲测试在 Linux 比对 `/proc/self/fd`） | 每浏览网卡 1 个组播套接字 | 1 个组播套接字 |
| 定时器 | **0** | 1 秒过期 ticker、一次性搜索截止时间 | 重试退避及每 60 秒重播 |
| 网络流量 | 0 | 查询按 1/2/4…60 秒退避 | 应答查询 + 60 秒重播 |
| 二进制 | 发现代码仍编入 Hub；P1 不拆发行组合 | — | — |

`TestUnusedSharingHasNoBackgroundTasks` 检查完整装配不启动功能任务；
`TestOptionalResourcesStopAndRestartTenTimes` 检查连续启停、发布撤销、关闭页面不停止分享和退出后不得重启。
`TestIdleDiscoveryIsFree` 不再允许空闲时保留两个协调循环。
发布撤销后任务退出，下次 Set 重新建立；浏览 Close 可重新打开，应用 Shutdown 为最终退出。

## 13. 第四轮复审（外部评审 `8e62e00` 的两项 P2）

### 13.1 R1 [P2] 缓存上限没有覆盖未完成状态

评审指出：`roomFor()` 只数完成候选，只有 PTR 的实例、以及每个不同 owner 名的 A 记录桶都
不受 128 限制，且完成时不再复核总量；`TestCacheBoundsUnderAFlood` 的 ID 生成器每 64 个
重复一次，从未真正触到边界。按生产 `parseRecords`/`apply`/`expire` 定点复现，4096 个
PTR 留下 2432 个 `entries`、4096 个 owner 留下 4096 个 `hosts`。

修复：

| 项 | 现在 |
| --- | --- |
| 未完成实例 | `MaxPartialInstances = 128`，满时拒绝新实例，不清已知条目 |
| 地址宿主桶 | `MaxHostBuckets = 128` |
| 候选总量 | 完成时再次检查 `MaxCandidates`，满时不加入、不驱逐 |
| 半成品寿命 | `partialTTL = 60s` 后丢弃（合法响应在毫秒级完成，不必留到 PTR 的 75 分钟） |

回归：`TestPartialPTRFloodIsBounded`、`TestUniqueAddressOwnerFloodIsBounded`、
`TestCompletingBeyondTheCapKeepsTheCap`、`TestPartialInstancesExpire`，并把
`TestCacheBoundsUnderAFlood` 的生成器改为真正互不相同、断言「正好守住 128」。
三处守卫撤掉后分别报 4096 / 4096 / 129，已验证。

顺带修掉一处一致性问题：`Candidate.Key()` 对实例名区分大小写，而缓存键不区分，
同一实例的两种大小写写法会生成两个候选。现在两边都按 DNS 规则小写比较。

### 13.2 S1 [P2] 提权助手的调用身份可伪造

评审指出：`VerifyLaunchCaller` 只比对命令行里的 PID/创建时间与镜像路径，同用户进程可以
读取真实桌面的身份并自行请求提权；配合自定义 JSON，助手会在用户同意 UAC 后为**任意程序**
创建规则。

在同一用户下，操作系统没有可靠办法区分"真正的桌面"与"同用户的另一个进程"，所以修复不
追求识别调用者，而是（a）让助手自己决定能授权什么，（b）收窄提权写的落点：

| 层 | 规则 |
| --- | --- |
| 程序路径 | 助手从**自己的安装位置**推导允许的桌面程序（`core/../connect-hub.exe`），操作里的 `ProgramPath` 必须与之相同，否则拒绝；推导不出就失败关闭 |
| 规则形状 | 只允许 apply 的入站、`private`/`private,domain`、单端口、RFC1918 网段、前缀 ≥ /8、规则 ID 必须是本程序前缀 |
| 文件落点 | 操作文件与结果文件必须同目录，目录名必须以 `connect-hub-firewall-` 开头，操作文件必须是**已存在的普通文件**（拒绝符号链接）；因为该文件必须由调用者创建，提权写入只能落在调用者本来就能写的目录 |

残余风险（据实记录）：同用户进程仍可让用户在 UAC 弹窗里批准一次「为 Connect Hub 自己
在某个私有网段开一个端口」。这不构成权限提升（提权者本来就能直接改防火墙），也不再能
把端口开给别的程序。Windows 实机仍未验证。

实现：`internal/relay/firewall_helper_policy.go`（平台中立，可在 Linux 上测试）+
`FirewallHelperMain` 在读取操作文件前先校验路径、读取后校验操作内容。

## 14. 第五轮复审（自查）

在修复第四轮两项之后继续按同两轴复查，发现 3 项。

| 编号 | 轴 | 问题 | 证据 | 修复 |
| --- | --- | --- | --- | --- |
| R4-1 [P2] | 规格 | §5.2 要求「发布地址必须能关联到接收接口的直连子网，忽略反射到其他子网的公告」，但接收侧只检查地址是否 RFC1918，没有和接收网卡比对 | `TestOnLinkOnlyAcceptsTheInterfacesSubnet`、`TestBrowserDropsOffLinkRecords` | `discovery.Interface` 增加 `Subnet`，应用侧用 `relay.SubnetOfAddress` 填；浏览器丢弃不在该网段内的 A 记录。没有子网信息时保持旧行为，子网信息损坏时失败关闭 |
| R4-2 [P3] | 标准 | 发现页每帧都会枚举网卡（`withoutOwnShare`、选择器），每帧多次 syscall | `TestAcceptanceBrowsingSetIsCachedAndCarriesTheSubnet` | 网卡列表按 1 秒 TTL 缓存在 `lanDiscovery` 中，选择器与过滤共用 |
| R4-3 [P3] | 规格 | 浏览集合被限制为 4 个网卡，而选择器用的是同一个函数，于是第 5 个网卡**根本选不到** | `TestAcceptanceInterfacePickerIsNotCapped` | 选择器改用不设上限的 `allLANInterfaces()`；真正建立浏览会话的上限提高到 8 并单独命名 |

R4-1 的两层落点：`OnLink`（纯函数，覆盖同网段/异网段/公网/坏输入/无子网/坏子网六种情形）
与浏览器记录过滤（用真实回调注入异网段 A 记录，列表保持为空，换成同网段后立即出现）。

## 15. 第六轮复审（自查）

| 编号 | 轴 | 问题 | 证据 | 修复 |
| --- | --- | --- | --- | --- |
| R5-1 [P2] | 规格 | 关闭发现时**保存失败**会让"本次运行不再广播"的抑制状态一直留着。用户随后关掉共享、再带着勾选重新开启，控制器认为已允许、面板显示「等待发布」，但**永远不会广播**，只能重启应用才能恢复 | `TestAcceptanceReEnableClearsTheFailedOffSuppression`（去掉修复后 3 秒超时） | 抑制状态记录它所属的分享代次（`suppressedGen`）；代次变了（新的 Enable/Suspend/Restore）抑制自动失效。面板开关显式打开时仍立即清除 |
| R5-2 | 证据 | 「等待 → 同一实例恢复 → 自动发布」与「退出先撤销公告」两条 §8.2 的路径此前没有端到端用例 | 新增 `TestAcceptanceWaitingShareAnnouncesWhenItStarts`（不调用任何 kick，只靠控制器的变更通知）、`TestAcceptanceShutdownWithdrawsTheAnnouncement` | — |

R5-1 的判定规则是"抑制属于某一次决定，不属于之后的所有决定"，实现上以 `View().Operation`
作为代次依据，避免它依赖某条具体的 UI 路径。

## 16. 第七轮复审（自查，UI 文案与渲染）

| 编号 | 轴 | 问题 | 证据 | 修复 |
| --- | --- | --- | --- | --- |
| R6-1 [P3] | 标准 | 开启表单的「允许同一网络的同事发现」被渲染成两个文本节点（`Checkbox` 自带文案 + 多余的 `.Label()`），同一句话在界面上出现两次 | `TestAcceptanceEnableFormHasNoDuplicateDiscoveryLabel`（断言只出现一次，并保留公开范围与默认名称说明） | 去掉多余的 `.Label()`；测试同时锁住两条必要说明不能被删 |

这一轮把「界面层」也纳入审查对象：前几轮集中在生命周期与协议，UI 只做了存在性断言，
没有检查重复/缺失文案。用例改成同时断言「必须出现」与「只能出现一次」。

## 17. 第八轮：Windows 实机日志（`not implemented on windows/amd64`）

用户在 Windows 上开启共享后，日志每 2 秒出现一次：

```text
[局域网发现] 发布失败：not implemented on windows/amd64
```

三个独立缺陷：

| 编号 | 轴 | 问题 | 根因 | 修复 |
| --- | --- | --- | --- | --- |
| W1 [P1] | 功能 | Windows 上**发现功能完全不可用** | 传输层用了 `golang.org/x/net/ipv4` 的 `SetControlMessage`，该包在 Windows 上直接返回 `errNotImplemented`（`ipv4/control_windows.go`），`openMulticast` 因此每次都失败 | 去掉对 `x/net/ipv4` 的依赖：`net.ListenMulticastUDP` 本身就会设置 `IP_MULTICAST_IF`、`SO_REUSEADDR` 并加入组播组，发送改用 `WriteToUDP`、接收用 `ReadFromUDP`。回环（同机两个实例互相可见）改用 `x/sys` 逐平台设置 `IP_MULTICAST_LOOP`（`mdns_loop_{other,windows}.go`） |
| W2 [P2] | 规格 | 失败后**每 2 秒重试一次**，退避完全失效，日志被刷屏 | 协调器每 2 秒把同一份公告再 `Set` 一次，`wantSeq++` 让 `retryPending` 判定失效，于是立刻重试 | `Set` 对**完全相同**的公告变成 no-op（`Clear` 同理）；真实变化（改名/换端口）仍然立即重试 |
| W3 [P3] | 标准 | 日志前缀重复：`局域网发现：局域网发现：发布失败` | 包内日志自带前缀，应用包装层又加了一次 | 包内不再带功能前缀，只由应用层添加；同一错误只记录一次 |

回归：`TestPublisherDoesNotReArmTheBackoffForTheSameAnnouncement`（撤掉修复：1 次 → 3 次）、
`TestPublisherLogsOneLinePerDistinctFailure`（撤掉修复：80ms 内记录 75 行）、
`TestPackageLogLinesCarryNoFeaturePrefix`。真实组播用例在本机仍通过（median 495µs）。

修复后 Windows 上应看到一次「正在发布」，而不是每 2 秒一条失败。**仍未实机验证**：
Windows 默认防火墙是否允许本程序收到入站 UDP 5353（发布方向是出站，不受影响）；
若同事端收不到公告，需要按 §9 的记录改用 `windns` 的 DNS-SD API。

## 18. 第九轮：`登录失败：资源域名不能是 IP 地址`（同事连不上分享）

现场日志（B 端）：

```text
[河投采购] 正在登录 192.168.201.135:65509 …
[河投采购] 登录失败：资源域名不能是 IP 地址
```

这不是发现失败，而是**同事连不上已开启的分享**：B 连的是 A 的分享地址，错误由 **A 的服务端**
在发布资源快照时抛出（`server.handleSessions` 调用 `snap.Validate()`，失败即回
`invalid_request`，客户端只能看到这一句）。

| 编号 | 轴 | 问题 | 根因 | 修复 |
| --- | --- | --- | --- | --- |
| R7-1 [P1] | 功能 | 只要宿主 VPN 的资源列表里存在 IP 字面量形式的"域名"，**该分享对所有同事都不可用**，而宿主自己看起来一切正常（Running） | `relayResources` 把会话快照的 `DomainRules`/`InternalDomains` 原样复制；`validateDomain` 拒绝 IP（正确），于是整份快照被拒。aTrust/EasyConnect 的真实配置里确实会出现这种条目 | 发布前调用新的 `ResourceSnapshot.DropUnusableDomains()`：丢掉不能当名称使用的条目，其余保留。丢弃只会**收窄**代理范围（地址本身若重要属于 IP 规则），不会放开任何东西；客户端的严格校验保持不变 |
| R7-2 [P2] | 标准 | 宿主端对"快照发不出去"**完全没有记录**，只有同事端能看到一行错误，分享者无从得知 | `Server.snapshot()` 直接返回错误 | 服务端按原因记录一次 `分享资源无法发布：…`，恢复时记录 `分享资源已恢复，可以接受同事加入` |

回归：`TestDropUnusableDomainsKeepsTheValidOnes`（严格校验仍拒绝未清理的快照，清理后通过且合法域名还在）、
`TestSharePublishesDespiteIPLikeDomainRules`（端到端：带 IP 域名的会话发布后客户端 `Open` 成功）、
`TestServerReportsAnUnservableSnapshotOnce`（撤掉记录：0 行；保留：1 行，恢复再 1 行）。

> R7-1 的修正只覆盖了 `DomainRules` 与 `InternalDomains`，**漏了 `StaticDNS[].Name`**：
> 静态 DNS 里只要有一位以 IP 字面量当名字，快照仍会被拒，同事看到的还是同一句错误。
> 现场复现与修复见 §19 R9-19。

## 19. 第十轮：Windows 环境复审（传输、生命周期、误拒）

本轮只看 Windows 上会真的出错、或只能靠实机才能发现的路径，并顺带清理前几轮留下的死字段。

| 编号 | 轴 | 问题 | 根因 | 修复 |
| --- | --- | --- | --- | --- |
| R9-1 [P1] | 规格 | Windows 上发现可能“静默为空”：`browser.Start` 成功、页面无错误，5 秒后显示「暂未发现分享」，用户无法区分「没人分享」与「被防火墙拦下」 | 发现是**双向**的：查询出站、应答入站，而程序只建了 TCP 入站规则（§9）。发布成功也不等于同事收得到 | 发现页空列表与宿主面板各加一行可诊断提示（专用网络 + 开启「网络发现」+ 允许 5353/UDP）。**不改 helper**：加 UDP 规则要改安全不变式，必须先有实机结论 |
| R9-2 [P2] | 标准 | mDNS 报文退回默认 TTL=1，RFC 6762 §11 要求 255；严格实现的接收端会丢弃 | `92a0029` 去掉 `x/net/ipv4` 时把 `SetMulticastTTL(255)` 一并删了 | `openMulticast` 重新设 TTL，走 `x/sys` 逐平台（`mdns_loop_*.go`）。宽度不统一：Linux 读 int、BSD 读单字节，非 Windows 实现先试 int 再退 byte |
| R9-3 [P2] | 标准 | 一张网卡开不了组播套接字就让**整次浏览失败**，面板直接报错；Windows 上断开的 VPN、Hyper-V 残留都很常见 | `mdnsBackend.Browse` 遇到第一个 `open` 失败就把已开的全关掉并返回错误 | 改为跳过失败网卡 + 记一行日志，至少一个成功即可；全部失败才报错，并列出拒绝了哪些网卡 |
| R9-4 [P2] | 标准 | `Start` 与 `Close` 竞态会泄漏一个 ticker goroutine（每秒 `cache.expire` 一次，进程内无人回收） | `startTicker` 在锁外安装，`Close` 可能已经先把 `stopTicker` 置 nil 并关闭 | 安装移到与 `b.session` 同一个临界区（`startTickerLocked`），并在其中再查 `closed` |
| R9-5 [P2] | 标准 | 放弃一次注册时 `res = <-resCh` 无上限等待：生产后端的 `Advertise` 不看 ctx，协调器可能被卡住，`Close` 只能靠 200ms 兜底 | `Backend` 接口承诺了 ctx，但 `net.ListenMulticastUDP` 无法中断 | `awaitAbandoned` 加 `abandonBudget`；超时后由有界的 `drainAbandoned` 接管迟到句柄并撤销；`Advertise/Browse` 入口先查 `ctx.Err()` |
| R9-6 [P3] | 安全 | `Announcement.Validate` 允许空 `Address`，打包时 `packDataA` 对 len==0 写 0 字节，对端整个报文 Unpack 失败 | 校验只比较了「非空时必须一致」 | 改为必填，并补一条表驱动用例 |
| R9-7 [P3] | 规格 | 公开名称里的反斜杠无法往返：TXT 是 DNS character-string，`\` 是转义引导符，同事端会看到另一个名字 | `lanname.Valid` 允许 `\`，`packTxtString` 把 `\DDD` 解成字节 | 在 `lanname.Valid` 拒绝反斜杠（与已有「不能有控制字符」同一位置），新增 `internal/lanname/name_test.go` 固定正反两面 |
| R9-8 [P3] | 标准 | 重新开始浏览后，上一代 parked snapshot 可能被当成新网络的列表应用 | `drainLANDiscovery` 的 `d.ui.snap.Generation == 0` 逃逸条件 | 在 `startLANDiscoveryBrowsing` / `closeLANDiscovery` 里清 `pending` 并重置 `snap`，去掉逃逸条件；同代 `>=` 保留（刷新不换代） |
| R9-9 [P3] | 规格 | 发现侧只用名字前缀判虚拟网卡，没有分享侧已有的 `/31`、`/32` 点对点判据；且同一网卡多个地址会开多个相同套接字 | 两处各自实现 | 两边共用 `newLANCandidates` 的分类 + 新增 `browsableAdapter`；浏览集合改为**每网卡一个套接字**；带子网的分类结果与地址列表同时缓存（避免每帧 syscall） |
| R9-10 [nit] | 标准 | 死代码：`lanDiscoveryUI.tab/busy/notice`、`Publisher.wg/inflight`、`wire.go` 的 `mdnsGroup`、`next == "自动选择"` 恒真分支 | 前几轮重构残留 | 删除（无测试引用） |
| R9-11 [P2] | 标准 | `Start` 只关旧 session，**不关旧的 `expireLoop`**：无网卡或后端报错两条失败路径下，旧 ticker 继续对新（空的）缓存 expire + publish，并活到下一次成功 Start 或 Close | 本轮复审第一轮 | 旧 ticker 与旧 session 一起在同一个临界区里摘除；`startTickerLocked` 只负责安装，并保留并发 Start 时的防泄灵关闭 |
| R9-12 [P2] | 标准 | `localLANBrowseCandidates` 用「长度相等」判断缓存一致性：长度相同、内容不同的两个列表会错配注解 | 本轮复审第二轮 | 缓存只由一个函数拥有，两个副本在同一把锁里写入；`localLANCandidates` 改为从注解列表派生，不再有第二条读路径 |
| R9-13 [P3] | 标准 | `virtualInterface` 不认识本程序自己的网卡（`ECH-<id>`、`aTrustHubN`、`ZJU Connect`），分类只靠「198.19/16 非 RFC1918」这层地址过滤兜住 | 本轮复审第二轮 | 前缀表补上三个名字；`TestVirtualInterfaceCoversEveryPlatform` 同时锁住正反两面 |
| R9-14 [P3] | 证据 | 同一 instance 同时存在两个存活 A 记录时，装配层只保留**一个**端点，选哪个由地址字典序决定（`cache.address` 取最小）。`TestAcceptanceOwnShareIsFilteredByAddress` 依赖这个顺序：作者机器 `192.168.31.61` 大于 `.240` 所以远端胜出，换成 `192.168.201.135` 就变成本机地址胜出、被正确过滤，用例失败 | Windows 实机跑 `go test .` 发现 | 用例改为先发旧地址的 goodbye（响应方换地址的真实行为）再发新地址，不再依赖地址顺序；**限制记入文档**：两个存活地址不能同时可见，要同时列出需要改成按地址分端点（本轮不做） |
| R9-15 [P3] | 证据 | `TestRelayPointOffersExplicitSystemProxy` 只在 Linux 通过：它把 `supportsSystemProxy()` 当唯一分支条件，但面板实际是三态（未就绪 / 已开启 / 可开启），Windows 上统一入口没起时只能显示「当前不可开启」 | Windows 实机跑 `go test .` 发现 | 断言改为「必须给出开启入口或说明原因」，并额外禁止不支持平台出现开启入口（比原来更严），不再用平台能力代替面板状态 |
| R9-16 [P1] | 安全/功能 | **重启后分享监听在 `0.0.0.0`（所有网卡），而不是用户选定的那张局域网卡**；同时 `c.identity.Address != address` 的「地址已变化」保护在重启后永远不会触发 | Windows 实机跑 `go test ./...` 时 `TestRestoreBindConflictIsBlocked` 变 running：Windows 允许 `0.0.0.0:P` 与已存在的 `127.0.0.1:P` 共存（两个方向都成功，已实测），Linux 会 `EADDRINUSE` 所以旧用例在 Linux 上「碰巧」通过 | 根因：`identityRecord` 只存 cert/key，`DecodeIdentity` 重建时丢掉 `Address`，于是 `StartServer` 回退到 `0.0.0.0`。改为从证书唯一的 IPv4 SAN 恢复 `Address`；`TestIdentityGenerateAndDecode` 加断言，`TestRestoreBindConflictIsBlocked` 成为回归 |
| R9-17 [P3] | 证据 | 两个只在 Windows 失败的用例假设：`TestFirewallRuleValidation` 用 POSIX 路径 `/opt/app/…` 当「绝对路径」（Windows 上 `IsAbs` 为假）；`TestRelayKnownCacheRoundTripAndCorruption` 断言 `0600/0700` 权限位（Windows 不报告 POSIX 位，建文件报 0666） | Windows 实机跑 `go test ./...` 发现 | 前者改用 `filepath.Join(t.TempDir(), …)` 生成平台绝对路径；后者把权限断言限定到非 Windows（round-trip 与损坏检测仍全平台跑） |
| R9-18 [P2] | 安全 | R9-16 的修复本身在「证书 SAN 不是恰好一个 IPv4」时返回**空地址**，而空地址不是安全默认值，它是 `0.0.0.0` 通配绑定——注释写的是「失败关闭」，实现是**失败开放** | 本轮自复审（三轮回读） | 改为拒绝解码：没有唯一 IPv4 SAN 的身份直接报错，控制器因此进入 `blocked("identity", …)` 而不是全世界监听；新增 `TestDecodeIdentityRequiresOneBoundAddress`（单地址可解、零个/两个/仅 IPv6 均拒绝） |
| R9-19 [P1] | 功能 | **同事仍然登录失败「资源域名不能是 IP 地址」**，即使装了带 §18 修复的版本：`Validate` 对 `DomainRules`、`InternalDomains`、**`StaticDNS[].Name`** 三处调 `validateDomain`，而 `DropUnusableDomains` 只清了前两个 | 现场日志（同事端 0.2.0）：`正在登录 192.168.201.135:58501` → `登录失败：资源域名不能是 IP 地址`；回读 `resources.go` 确认第三个字段无人清理 | `DropUnusableDomains` 补上 `StaticDNS`（名字不能当域名的记录丢掉；这类记录本来也无法按名字被解析），`TestDropUnusableDomainsKeepsTheValidOnes` 加入静态 DNS 用例并校验清理后 `Validate()` 通过 |
| R9-20 [P1] | 功能/文档 | 同一现场的第二条失败：`登录失败：连接分享主机超时`。**防火墙规则存在且正确，但网络类别是「公用」**：规则限定 `Profile=Private`，Windows 在 Public 网络上不应用它，于是 SYN 被丢（超时而不是拒绝） | 宿主实机取证：`ConnectHub-LANShare-58501-… :: TCP/58501 Profile=Private remote=192.168.200.0/23 Enabled=True`；`Get-NetConnectionProfile` 为 `WLAN( Searun 2 ) = Public`；而 Linux→宿主 的同机连接 1ms 成功（回环不过入站过滤），两相对比定位 | 代码侧已把网络类别写进 §9 与本节；**面板仍会显示「已放行端口」而实际不生效**，建议后续加一次非提权 `Get-NetConnectionProfile` 检查（每会话一次、约 600ms、后台 goroutine）并在「公用」时改为警告；当下处置：把该网络设为「专用」（或换到专用网络） |
| R9-21 [P2] | 标准 | `authenticateClient` 的注释写「校验并续租」，实际只有 `/v1/status` 心跳会续租：**任何只轮询资源 / 开隧道、不发心跳的客户端会在第 15 秒被静默踢掉**，错误是「客户端会话已过期，请重新认证」，把真正原因藏起来 | 现场实测两次：Linux 探针登录后每秒发 `/v1/resources`，均在 `ClientLease=15s` 后报 `session_expired`、既有隧道 EOF；回读 `clients.go` 确认只有 `touch()` 续租、而 `touch` 仅在 `handleStatus` 调用 | 认证即续租：`authenticateClient` 在 `lookup` 成功后 `touch`，失败才返回 `session_expired`；`TestAnyAuthenticatedRequestRenewsTheLease`（80ms 租约、每 1/3 租约发一次请求、随后静默必须过期）与 `TestShareTokenIsNotASessionToken` 锁定正反两面 |
| R9-22 [P2] | 标准 | 条件刷新从来没有条件过：服务端把 ETag 当 `"<revision>"`（RFC 7232），客户端却把裸 revision 当 `If-None-Match` 发出去，`304` 分支是死代码，每次「刷新」都重传整份快照 | 探针按 `notModified` 判定代次变化时立刻误报，回读 `server.go`/`client.go` 发现两边格式不一致 | `quoteEntityTag` 在客户端补引号；服务端比较时容忍带引号与不带引号；304 同时回写 `ETag`；`TestResourcesConditionalRefreshReturnsNotModified` 覆盖裸/带引号/空/过期四种 |
| R9-23 [P2] | 规格 | 宿主关闭共享后，同事看到的是裸传输错误：`无法连接分享主机：Post "https://…/v1/sessions": dial tcp …: connect: connection refused` —— 混着 HTTP 动词、URL 和系统措辞，既不说明「共享已关闭」，也不区分「同网段不可达」与「被防火墙丢」 | 现场实测：关闭共享后客户端复现该原文；同时确认宿主侧 58501 已停止监听、`ConnectHub-*` 规则已清理（0 条）、外部拨号返回 `Connection refused` | `describeHostDialFailure` 归一为四种可行动结论（拒绝/不可达/被重置/超时），覆盖 Unix `connection refused` 与 Windows `actively refused` 两种措辞；`TestDescribeHostDialFailure` 断言结论里不得残留 `dial tcp`/`Post `/`https://`/`connectex`，`TestClosedShareReportsAHostRefusal` 用占用后释放的端口做端到端验证 |

关于缓存上界的复查结论（原报告列为缺陷，**本轮核实后不成立**）：`transitions` 里
`len(c.emitted) >= c.max` 在原代码中只可能在 `stale` 为空时命中（`emitted` 从来不超过 `max`），
所以“先发 removed 再加不进去”的路径不可达。仍然改成先判定后修改，把“不删而不加”写成不变式，
行为不变。

本轮新增/扩充的用例：`TestBrowseSkipsAnInterfaceItCannotOpen`（一张坏网卡不影响其余；全失败时
报错并点名）、`TestValidRefusesABackslash` / `TestValidKeepsAcceptingOrdinaryNames` /
`TestDefaultIsAlwaysValid`、`TestAnnouncementRejectsUnusableValues` 新增「没有地址」、
`TestVirtualInterfaceCoversEveryPlatform` 新增本程序网卡名（R9-13）。

本节先由一轮环境复审成稿（R9-1…R9-10），随后又做了三轮自复审：第一轮查生命周期
（得 R9-11），第二轮查平台与缓存读取（得 R9-12、R9-13），第三轮核对测试影响面与
文档一致性（修正 §2 选型表中已失效的 `x/net/ipv4` 与「新依赖：无」、统一 R 编号）。

仍未验证（需实机，代码审查替代不了）：§9 的入站 5353 结论、TTL 255 在 macOS/Windows 上的
实际生效值、Bonjour/Avahi 共存、跨机发现。

Windows 实机首次跑根包测试（`go test .`）暴露了两个**既有**的、只在 Windows 上失败的用例
（R9-14、R9-15），均已按「不依赖机器地址顺序 / 不依赖平台能力代替面板状态」修正；
随后跑全仓（`go test ./...`）又暴露一个**产品缺陷**（R9-16：重启后绑 0.0.0.0）与两个
Windows 语义假设（R9-17），均已修复。

最后在 WSL Debian 上做了 Linux 侧验证，包含 `-race`、真实组播用例与 TTL 读回（见 §19.1）；
本轮自复审又发现 R9-18（R9-16 的修复在异常证书上会退化成通配绑定，已改为拒绝解码）。

### 19.1 验证记录（Windows 11 实机 + WSL Debian + 真实分享链路）

**自动化门禁**

```text
# Windows 11（go 1.27.3 windows/amd64）
$ go test . -count=1          → ok  github.com/ehzyil/connect-hub
$ go test ./... -count=1      → ok  17 个可测包全部通过

# WSL Debian（go 1.27.3 linux/amd64，gcc 14.2，16 核，镜像网络 eth7=192.168.201.135/23）
$ go build ./...                                    → exit 0
$ go vet ./internal/relay/discovery/ ./internal/relay/ ./internal/lanname/ ./internal/store/
                                                    → exit 0
$ go test ./... -count=1                            → 19 个可测包全绿（比 Windows 多出只在 Linux
                                                    编译的 capture/resolved；root 15.846s，
                                                    relay 5.943s，discovery 2.359s，store 0.705s，
                                                    vpn 39.292s）
$ go test -race ./internal/relay/discovery/ -count=1 → ok（无 DATA RACE）
$ go test -race -run "Discovery|LANShare|OwnShare|Shutdown|Idle" . -count=1 → ok
$ go test ./internal/relay/discovery/ -run TestLive -v -count=1
    --- PASS: TestLiveDiscoveryLatency  (20 轮，接口 eth7，min=1.25ms median=1.76ms p95=2.45ms)
    --- PASS: TestLiveMulticastRoundTrip
```

**真实分享链路实测**（Linux 客户端 → Windows 宿主 → 宿主 VPN → 内网；临时探针用仓库自己的
`relay.Client`/`Diagnose`，跑完删除）

| 场景 | 结果 |
|---|---|
| 登录 + TLS 钉扎 | 指纹与口令一致；错指纹被挡在握手前，并把收到的指纹打出来；错口令 → `invalid_credentials` |
| 内网资源授权 | 公网 `36.99.195.118:8443` → `resource_denied`（按设计）；`192.168.61.38:8080` 在放行范围内 |
| 内网 HTTP 往返 | `GET /login?from=%2F` → `200 OK`，`Server: Jetty(12.0.18)`、`X-Jenkins: 2.504`、正文为 `Sign in - Jenkins`；同一地址**直连**是 `no route to host` |
| 并发 | 8 条隧道同时开 → 8/8 成功，98ms |
| 目标侧故障 | `connection refused` / `host unreachable` 被归类为可行动原因（R9-19、R9-23） |
| 会话吊销 | `DELETE /v1/sessions/current` 后立即拨号 → `session_expired` |
| 宿主自身入口 | `127.0.0.1:1080` 从 WSL 可用：内网 200/144ms、公网 200/745ms（系统代理分流生效） |
| 共享口令时序 | 重启应用 + 重登 VPN 后口令**完全一致**（sid/token/证书/端口均持久化）；**关闭共享**则删身份与口令，旧口令作废 |
| 关闭共享后 | 宿主：监听消失、`ConnectHub-*` 规则清空（0 条）；客户端：`分享主机拒绝了连接：共享可能已关闭，或宿主已退出` |

`dnsServer` 为空（该网关不提供 DNS）时，诊断现在会明确说「本次分享不提供 DNS」，避免把
「宿主没给 DNS」误判成「解析坏了」。

TTL 255 的生效值：Linux 上用与 `mdns_loop_other.go` 相同的 int 形式设置后读回
`ttl=255, loop=1`（临时探针，已删除），说明内核接受 4 字节形式，byte 回退在 Linux 上不会
被用到。

仍属未验证（不得当作已支持）：

| 项 | 现状 | 能补上的方式 |
|---|---|---|
| 入站 5353 是否被 Windows 防火墙拦（§9、R9-1） | 未测；同机回环组播绕不过接口入站过滤，不能用来证明 | 两台真机 + 默认防火墙配置 |
| 跨机发现 / 跨 AP / AP 隔离 | 未测；所有实测都是同一主机内的回环组播 | 两台真机 |
| 与 Avahi/Bonjour 共存 | 未测；WSL 内无 responder 运行 | 装有 Avahi 或 Bonjour 的主机 |
| macOS 分支的 TTL/回环与本地网络权限 | 未测；本轮只有 Windows 与 Linux 两个平台 | macOS 实机 + `scripts/package-mac.sh` 产物 |
| 规模（10 主机 ×10 浏览端） | 未测 | 同网段压测 |
