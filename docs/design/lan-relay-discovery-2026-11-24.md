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
