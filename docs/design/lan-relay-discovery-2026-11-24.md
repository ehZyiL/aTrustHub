# 局域网分享：自动发现（已实现）

状态：已实现并通过自动化验收；跨机与平台权限仍需实机覆盖（见 §9）。日期：2026-11-24。

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
| 传输 | 自建 socket：每网卡一个 `224.0.0.251:5353` 组播套接字（`golang.org/x/net/ipv4`） | 需要逐网卡收发、TTL 控制、goodbye、接收接口归属；这些是库最容易缺失的部分 |
| 新依赖 | 无 | `go.mod` 未新增任何模块 |
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

`Controller` 的通知（`app.lanShareChanged`）触发一次无阻塞 kick，后台协调器读取最新状态；
另有 2 秒兜底 tick。渲染循环、页面是否打开都不参与生命周期正确性。

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
| Windows/macOS 实机发现 | 只做了交叉编译与单元测试 | 两台真机、实际发布包、系统防火墙默认配置下的收发 |
| macOS 15 本地网络权限 | 已在 `scripts/package-mac.sh` 写入 `NSLocalNetworkUsageDescription` + `NSBonjourServices` | 允许/拒绝/恢复，拒绝后业务 TCP 的表现 |
| Windows 纯 Go 后端入站 5353 | 未实测；若默认防火墙拦截入站，需要评估改用 `windns` | 普通用户、无放行规则下的收发记录 |
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

新增功能必须先回答「对不需要它的用户增加什么」，这里给出实测值而不是估计。

| 项 | 空闲（从未开启） | 打开发现页 | 开启共享 + 允许发现 |
| --- | --- | --- | --- |
| goroutine | 2（发布协调器 + 状态监督，都阻塞在 `select`） | +每网卡 1 个接收循环 + 查询循环 | +发布循环 |
| 堆 | ≈9 KB | 受缓存上限约束（128 条） | 同左 |
| 文件描述符 | **0**（`TestIdleDiscoveryIsFree` 在两次兜底 tick 前后比对 `/proc/self/fd`） | 每浏览网卡 1 个组播套接字 | 1 个组播套接字 |
| 定时器 | 1 个 2 秒 ticker，只做一次加锁判断，不重绘 | +1 秒过期 ticker | +每 60 秒重播 |
| 网络流量 | 0 | 查询按 1/2/4…60 秒退避 | 应答查询 + 60 秒重播 |
| 二进制 | +296 KB（+0.93%，含 `miekg/dns` 的链接） | — | — |

本轮为此修掉一处真实回归：协调器的 2 秒兜底 tick **顺带触发了整窗重绘**，
等于让每个用户每两秒重建一次界面；现在只在「发现页打开且仍在 5 秒搜索窗内」重绘，
其余全部事件驱动。`TestIdleDiscoveryIsFree` 把这个约束固定下来（空闲无重绘、无 fd、
最多 2 个 goroutine、退出后回到基线）。

若要把空闲成本压到 0，可把协调器改成首次使用时创建（约 30 行），代价是新增一条
生命周期路径——上一轮复审的 P1 恰好出在这类路径上，因此默认不做。

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
