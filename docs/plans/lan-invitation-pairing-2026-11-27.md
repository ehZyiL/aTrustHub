# 局域网限时邀请码与独立设备授权

日期：2026-11-27。分支：`refactor/component-boundaries`。状态：**needs_review**，等待用户跨机验收与安全复核。未推送、发布或启动额外 Hub。

实现提交：`4950d7737f37d03549a9e947914f04428715c2f9`（49 个文件，16 个新建、33 个修改）。原有 `go.work`、`go.work.sum` 不在提交中。

交付前 P1/P2 修复：`fa4d567`、`e1ce571`。底层未认证 TCP 已改为独立可回收预算，取消配对会失效旧结果邮箱；详见 [修复与验证记录](lan-invitation-pairing-fixes-2026-11-27.md)。此自动验证不代表用户验收，也不是 DS 的真实程序实测。

后续响应修复：`207f5b6` 修复主机管理面板的每秒刷新；`594f847` 修复共享启动等待占用状态锁、已取消管理请求仍排队执行，以及发现结果/旧面板结果误结束暂停或恢复操作。最新完整构建为 `build/share-lifecycle-fix-20261127/`，验证见同一修复记录末节。

## 结果与兼容性

发现支持配对的主机后，用户输入短码，双方核对会话校验码及公钥派生设备标识，主机逐台批准，客户端确认领取后自动连接。每台客户端自行生成独立 Ed25519 私钥，主机只保留公钥验证表示。后续重连无需邀请码。

旧完整口令仍使用 v1；它属于共享授权，持码者不能逐台识别或独立撤销。`Disable` 原有“销毁分享身份和完整口令”的语义保留。新增持久化暂停/恢复，暂停保留设备授权，但会关闭当前服务实例，使当前邀请码及临时配对请求立即失效；恢复后新设备需重新生成邀请码。撤销全部 v2 设备是带明确确认的独立操作，不使 v1 完整口令失效。

发现 `dv=1`、分享基础协议 `pv=1` 和 `relay-process-v1` 不变。新增可选 TXT `pair=opaque-ed25519-v2`，旧解析器原本忽略未知键。只有 sidecar 的 `ready` 明确声明支持配对时才公告能力。新客户端选定 v2 后，认证失败不会自动退回 v1；用户仍可主动切到粘贴完整口令入口。

## 原语核查与协议边界

采用 `github.com/bytemare/opaque v0.18.0`，未自行实现 PAKE。核查了该固定模块的 README、LICENSE、配置、示例、注册、登录与反序列化 API：实现声明遵循 RFC 9807 OPAQUE，MIT 许可，维护者为 RFC 作者之一；其 README **明确声明尚未经过独立安全审计**。本实现也未经外部密码学审计，自动测试不能代替该审查。

主源参考：

- RFC 9807：<https://www.rfc-editor.org/rfc/rfc9807.html>
- 固定版本源码与说明：<https://github.com/bytemare/opaque/tree/v0.18.0>
- 固定版本许可证：<https://github.com/bytemare/opaque/blob/v0.18.0/LICENSE>

使用库的默认 Ristretto255/SHA-512/Argon2id 配置。每次邀请码有独立临时 OPRF seed、服务端密钥材料和注册记录，仅在内存保留。主机创建数字码完成本地注册后，不将数字码放入配对状态、日志或广播；本地显式创建结果经私有 IPC 返回 UI 显示。新依赖及其新增间接依赖的许可文件纳入三个平台的打包脚本。

协议流程：

1. 客户端为本次申请生成 Ed25519 密钥，建立专用 TLS 1.3 WebSocket `/v2/pair/start`。初始自签证书只检查格式、有效期、用途和实际地址，不从发现 TXT 获取信任根，不发送明文 PIN。
2. 主机发送邀请 ID、ShareID 和当前证书指纹。双方把 TLS exporter、这些主机字段、设备公钥与显示名称编码并散列为 OPAQUE `Context`。设备私钥签署同一绑定值，主机在执行 PAKE 前验证持钥证明，不能凭自报公钥接管他人的请求。
3. 客户端通过 KE2 验证主机、得到会话密钥；**在发送 KE3 前**，配对 sidecar 向父进程发送 `saving` 检查点。UI 将私钥 seed 写入现有 SecretStore，受认证的主机指纹写入节点配置，配置落盘成功后才发送 `pair-stored`。写入失败关闭配对，不产生可批准请求。
4. 主机验证 KE3 后才使用会话密钥、建立待批准请求。随后轮询、状态和领取确认全部留在这条 WebSocket，以方向、递增序号、负载的 HMAC-SHA256 认证。双方显示会话密钥派生的 12 位十六进制校验值和 SHA-256 公钥设备标识。名称只供显示，不是身份。
5. 主机在锁内检查邀请容量和设备上限，原子保存完整公钥授权表成功后才置批准并扣一次名额。客户端收到批准后确认领取，确认成功再自动建立业务会话。批准响应或 ack 丢失时，步骤 3 的检查点仍允许新进程持钥重连；主机无需重发任何明文设备秘密。
6. 业务认证 `/v2/sessions` 每次新建一条被已认证指纹钉住的 TLS 连接，Ed25519 签名绑定该连接的独立 exporter、ShareID、指纹和业务认证域。服务端强制关闭该 HTTP 连接；自动重试不会把旧证明带到新连接。随后沿用已有短租约和受限业务隧道协议。

配对握手、批准查询、领取确认的 exporter **只属于最初的 WebSocket TLS 连接**。HTTP 连接池、轮询重连或另一个进程不能继承它；断线即终止该临时会话。长期设备重连使用新的签名证明，而不是复用 PAKE 会话密钥。v2 的内存 credential DTO 不可通过 `ShareCode.String()` 导出成完整口令。

## 状态、持久化与资源

参数集中在 `internal/relay/contract/pairing.go`：

| 资源 | 默认策略 |
| --- | --- |
| 未认证 TCP/TLS/HTTP | 独立 32 条；满额回收最早接收且仍未认证的连接，让新连接有机会完成认证；TLS/初始请求 5 秒，进入配对握手后延长至 20 秒 |
| 已认证控制 TCP | 独立 40 条（在线设备上限的 4 倍）；成功认证后迁移并释放未认证预算；HTTP 空闲 15 秒，普通请求读取最多 5 秒 |
| 已认证隧道 TCP | 独立 256 条；CONNECT 认证后迁移，失败响应关闭连接，成功 hijack 的连接到隧道结束或 listener 关闭才释放 |
| 已认证配对 WebSocket | KE3 验证后迁移至独立 16 条；不再占未认证 TCP/PAKE 槽位，按请求到期或关闭释放 |
| 邀请码 | 8 位逐位均匀随机数字，允许前导零 |
| 邀请有效期/容量 | 5 分钟 / 成功批准并持久化 5 台新设备 |
| 待批准与最近请求 | 独立最多 16 条，每条 5 分钟；超时状态额外保留 1 分钟供 UI 查看 |
| 未认证 PAKE 握手 | 最多 8 个，20 秒；认证后转入独立请求额度 |
| 持久化设备 | 最多 128 台，文件最多 128 KiB |
| 配对限速 | 每来源 6 次/分钟，突发 5；全局 60 次/分钟，突发 12 |
| 已认证请求轮询 | 最短 200ms；生产客户端每秒查询一次 |
| 主机授权面板刷新 | 面板可见时每秒通过本地管理接口读取一次；同一时刻至多一个当前读取，慢读取不重复发起。倒计时独立续订重绘，后台读取不禁用操作按钮；显式操作替换读取并隔离旧回包 |
| 本地操作取消与启动响应 | 等待生命周期锁、配对状态锁或 IPC 写锁时支持取消，发送前再次检查；组件启动及失败资源清理不占用状态锁。面板重开后旧结果不能更新新面板，发现偏好与共享操作分别结束各自忙状态 |
| 限速来源表 | 最多 4096 项，清理超过 10 分钟的旧来源 |
| 在线设备 | 沿用独立的 10 台上限 |
| 业务隧道 | 沿用总 256 / 单租约 64；DNS 另计 |

错误尝试按来源退避，不取消整个邀请。来源超限检查在全局扣额之前，单个已限速来源持续重试不会继续耗光全局桶。网络攻击仍可能使连接/握手资源暂时繁忙，这些上限不等同于抗网络层 DoS 保证。

新建且未认证的 HTTP 响应（含 404）显式声明关闭连接，不能靠空闲 keep-alive 长期占位。listener 对已交付、尚未交付和 hijack 后的 socket 保留关闭归属；关闭不等待容量许可。上述四类预算合计最多 344 条被登记连接，内核 accept 队列及一次接收/回收交接不属于该登记数。有限的未认证占位不再与已认证控制和业务共享许可；持续竞争的新连接仍可能中断尚未认证的合法握手，CPU、带宽、文件描述符及已认证配额也有各自边界，不能承诺任意洪泛下无条件可用。

邀请取消、过期、耗尽只阻止新握手，不撤销设备。已通过 KE3 的请求仍可在自己的期限内审批，扣其原邀请的容量；生成新邀请码不会把旧请求转到新名额。新启动只加载持久化设备，邀请和请求不恢复。

授权表保存到 `relay-devices/<ShareID>.json`，沿用项目 `writeFileAtomic` 的临时文件、Sync 与 Rename 路径。客户端私钥沿用现有系统凭据库/项目配置的安全存储后端，不放进配置或发现报文。系统凭据库不可用时的文件后端与权限行为沿用既有策略。

写入失败时不返回批准成功、不扣成功名额。若写入已经落盘而响应丢失，保持待协调候选事务，后续本地控制操作重试同一完整候选表，再一次性应用状态；协调前冻结其他授权变更，不能覆盖未知持久化结果。无须重新传送设备秘密。

单台撤销首先隔离该设备、删除其在线租约、取消挂起拨号并关闭现有隧道，再持久化删除公钥。写入失败必须显示错误且重试；本进程立即拒绝目标设备，其他已授权设备仍可认证。**若撤销未能持久化就重启，磁盘上的旧授权可能恢复**，不能把失败当作已完成撤销。暂停态仍可管理持久化设备。

在线设备身份是 `device:` 加公钥摘要，与短期租约 token 分离；同设备重连替换原租约，不增加在线设备计数。v1 自报客户端 ID 禁用这个保留前缀。撤销或认证失败不会降级为无认证或错误直连。

## 自动验证

实际运行环境：Windows Go 1.27.4；WSL Debian Go 1.27.3 + gcc 14.2。Windows 无 C 编译器，race 在 WSL 执行。项目是 MyGo 纯 Go UI，没有 npm 前端；UI 检查由桌面测试和 Hub 构建覆盖。

| 命令/范围 | 结果 |
| --- | --- |
| Windows `GOWORK=off go test -mod=readonly ./... -count=1` | 全量通过，包含真实本机 discovery、sidecar 和边界检查 |
| Windows `GOWORK=off go vet -mod=readonly ./...` | 通过 |
| `git diff --check` | 通过 |
| `go run ./scripts/buildtool -development -out build/pairing-review` | Windows/amd64 全组件构建通过，含协议生成一致性与固定内核校验、manifest |
| Linux/amd64、macOS/amd64 的 `cmd/connect-hub`、`cmd/app-relay` | `CGO_ENABLED=0 go build -mod=readonly` 交叉构建通过；未运行这些二进制 |
| WSL `go test -race`：relay/...、store、model | 通过，无 race 报告 |
| WSL `go test -race`：本次配对 UI 与发现入口定向测试 | 通过，无 race 报告 |
| WSL 完整 desktop race | 见下方具体限制，不计为全量通过 |
| `bash -n scripts/package-{linux,windows,mac}.sh` | 语法检查通过；未发布或制作发行包 |
| 新增 9 个模块许可文件定位 | 全部 `go list -m` 定位并确认存在 `LICENSE` |

提交后曾在全量测试与构建并发运行时遇到一次既有 `TestWorkerDNSConcurrentRepliesBypassLoginQueue` 的启动超时，失败发生在 `internal/vpn/dns_test.go:34` 的 1 秒测试进程启动期限内。随后该用例 `-count=20` 单独复测通过，停止并发构建后的最后一次相同全量测试命令也全部通过（desktop 27.118 秒、relay/process 23.109 秒、vpn 9.262 秒）。没有更改该测试或放宽期限；资源竞争只是可能原因，未把它当作已证明的根因。

关键验证命令（PowerShell 7）：

```powershell
$env:GOWORK='off'
go test -mod=readonly ./... -count=1
go vet -mod=readonly ./...
go run ./scripts/buildtool -development -out build/pairing-review
git diff --check
wsl --cd /mnt/d/Programming/Projects/Go/easy-connect/aTrustHub --exec env PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin GOWORK=off CGO_ENABLED=1 /usr/local/go/bin/go test -race -mod=readonly ./internal/relay/... ./internal/store ./internal/model ./internal/desktop -count=1
wsl --cd /mnt/d/Programming/Projects/Go/easy-connect/aTrustHub --exec env PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin GOWORK=off CGO_ENABLED=1 /usr/local/go/bin/go test -race -mod=readonly ./internal/desktop -run 'TestPair|TestDiscoveryPairing|TestCoreDependencyGraphExcludesOptionalRuntime|TestDesktopDoesNotLinkCleanupService|TestDesktopLivesBehindCmdEntryPoint|TestSharePageAcceptsClientAndShowsUnavailableState|TestAcceptanceEnableFormHasNoDuplicateDiscoveryLabel' -count=1
```

第一条 WSL 命令整体 exit 1（下述两项桌面失败），第二条定向命令 exit 0。不要把两者合并成完整 race 通过。

主要新增验证：16 条并发审批只有 5 次成功；重复批准与落盘后响应丢失协调；邀请、请求、重启生命周期；两同名设备独立身份；领取响应完全丢失后使用检查点重连；凭据/配置保存失败不发送 KE3；未确认节点重试替换和已确认节点保护；领取成功触发连接；请求 16 与握手 8、在线 10、邀请 5、业务额度独立；在线满额仍可持久化新设备，旧设备重连不占新位；撤销失败隔离、撤销全部、v1 兼容。

安全测试实测 TLS 终结代理改写主机指纹和设备公钥、转发真实 KE1/KE2 仍无法通过 PAKE；跨 TLS 连接重放 Ed25519 证明被端点拒绝；冒用已配对设备公钥但无私钥被拒绝；HMAC 方向/序号重放被拒绝；错码不创建请求、不耗业务额度、不泄漏秘密；公网监听不存在本地管理路由。真实 sidecar 测试还覆盖父进程持久化故障、重启重连、取消检查点回收进程、撤销取消父 broker 挂起拨号及其他设备隔离。

最终完整 WSL desktop race（102.513 秒，exit 1）中 `TestLiveDiscoveryJoinEndToEnd` 出现 B 会话上线超时，`TestLANSharePanelRecommendsTheReachableAdapter` 因真实 WSL `br-*` 网卡与期望选择不同失败，运行环境还提示缺少 `libpango-1.0.so.0`，没有 race 报告。Windows 同一套正常测试通过。未据此修改无关网卡或 UI 行为，也未将 WSL 完整命令标为通过；这不是经过基线对照证明的无关失败。

## 可复现手动验收（尚未执行）

1. 准备同一局域网主机 A 和客户端 B、C，使用本次完整构建并保留相邻 `core/connect-hub-relay`，分别使用自己的现有数据目录。由用户自行启动应用；A 登录可共享的 VPN 接入点，开启共享与允许发现。
2. A 打开“邀请码与设备授权”并生成邀请码：检查 8 位数字、约 300 秒和 5 个名额。B、C 在“同事分享 → 发现局域网分享”选择 A，输入同一码，可故意使用相同显示名称同时申请。错误码先测试一次，应提示认证失败且不取消 A 的整个邀请。
3. A、B、C 分别核对每条请求的会话校验码和完整设备标识。两台设备标识必须不同，不能只凭同名批准。A 批准 B、拒绝 C；B 点击“确认领取并连接”，应自动上线，C 显示拒绝并能重新申请。
4. B 访问一个 A 授权的 TCP 目标并保持连接；C 重试并获批后也连接。A 单独撤销 B：B 现有隧道立即断开、后续连接失败；C 保持正常。再次批准 C 或 C 重连不得重复扣名额或增加在线计数。
5. 在同一邀请下累计批准 5 台新设备，第 6 台不得超额成功。可用多个客户端或独立测试数据目录重复，切勿复制同一设备私钥来模拟不同设备。生成新邀请码应有独立 5 台容量。
6. A 取消邀请码或等待 5 分钟：新申请被拒，已有设备继续使用；既有待批准请求按自己的剩余期限处理。请求超过自身 5 分钟显示超时，不能再批准。
7. A 暂停共享：设备断线，但设备列表与授权保留；当前邀请码和临时配对请求立即失效，无须等重启。退出并重启 A 应仍保持暂停；恢复共享后 B/C 中未撤销设备不用输入邀请码即可重连，新设备需重新生成邀请码。重新启动 A 同样清空邀请和临时请求。
8. 在 B 本地已保存但 A 尚未批准时，结束 B 的配对子进程/关闭面板；A 随后批准，B 应能通过节点列表持钥连接。也可在批准后、领取响应到达前中断连接，重连应成功且已确认节点不能被静默换钥。
9. 让用户在测试数据目录中模拟授权文件无法写入：批准应显示持久化失败且不扣名额；恢复写权限并重试，仅扣一次。撤销写失败必须明确报错，当前运行中目标立即隔离；持久化成功前不要把重启后的撤销视为已完成。
10. 用原 v1 完整口令导入另一测试客户端验证兼容。显式“撤销全部已配对设备…”不应使旧 v1 口令失效；“关闭共享”应销毁旧身份、使全部旧口令和设备授权失效，再开启应建立新身份。
11. A 保持“邀请码与设备授权”面板可见至少 10 秒：倒计时应持续变化，后台刷新不应使“生成邀请码”“取消邀请码”“暂停共享”或审批/撤销按钮反复变灰。在一秒刷新间隔内生成、取消并再次生成邀请码，随后保持无操作，新的待批准请求仍应自动出现；关闭面板后停止读取，重新打开应读取当前状态，旧回包不得覆盖新邀请码或错误提示。
12. 开启或恢复共享尚未完成时，页面应能持续绘制并响应。暂停/恢复尚未完成时，发现偏好或公开名称的保存结果不得提前启用另一轮共享操作；关闭再重开面板后，旧操作的成功或失败不得关闭新面板、清除新操作的忙状态或覆盖新错误提示。

尚未手动启动真实 Hub/VPN、操作系统凭据库、改变防火墙或做跨机网络体验；macOS/Linux 只有交叉构建，跨机发现、多播权限、证书到期和真实业务负载仍需用户验收。覆盖率百分比未测量，不宣称达到 80%。

## 文件清单

核心代码引用：`internal/relay/contract/pairing.go:9` 的集中策略；`internal/relay/pairing_wire.go:87` 的 exporter/身份绑定、`:295` 的 KE3 前持久化检查点；`internal/relay/pairing_state.go:147` 的本地管理、批准事务与单设备撤销；`internal/relay/device_auth.go:37` 的设备授权检查和租约创建互斥；`internal/relay/process/pairing.go:256` 的专用配对子进程；`internal/desktop/pairing_view.go:332` 的客户端安全保存与回滚；`internal/relay/pairing_security_test.go:113` 的实际中间人转发测试；`internal/relay/process/pairing_test.go:204` 的跨进程挂起拨号撤销测试。

### 新建

| 文件 | 用途 |
| --- | --- |
| `internal/relay/contract/pairing.go` | 策略、独立模型、管理与客户端接口 |
| `internal/relay/pairing_state.go` | 邀请、请求、原子授权、撤销与协调 |
| `internal/relay/pairing_wire.go` | 专用通道、OPAQUE、持钥证明、认证轮询和领取 |
| `internal/relay/device_auth.go` | exporter 绑定的设备会话认证 |
| `internal/relay/pairing_controller.go` | 本地管理、暂停/恢复和暂停态设备管理 |
| `internal/relay/process/pairing.go` | sidecar 配对、管理 RPC、公钥持久化 broker |
| `internal/store/relay_devices.go` | 有界公钥授权持久化 |
| `internal/desktop/pairing_view.go` | 主机管理、客户端配对/领取与安全保存 UI |
| `internal/relay/pairing_test.go` | 原子容量、故障、端到端、v1 和重放测试 |
| `internal/relay/pairing_security_test.go` | 中间人、证明重放、持钥、检查点、远端管理隔离 |
| `internal/relay/pairing_lifecycle_test.go` | 暂停、重启、额度、退避与失败隔离测试 |
| `internal/relay/process/pairing_test.go` | 真实 sidecar 端到端与挂起拨号撤销 |
| `internal/relay/discovery/pairing_test.go` | 可选能力与旧解析兼容 |
| `internal/store/relay_devices_test.go` | 原子存储、路径、取消、大小与数量界限 |
| `internal/desktop/pairing_test.go` | UI、保存故障、重试、领取与入口测试 |
| `docs/plans/lan-invitation-pairing-2026-11-27.md` | 本说明与验收清单 |

### 修改

| 文件 | 用途 |
| --- | --- |
| `go.mod`、`go.sum` | 固定 OPAQUE 与必要依赖 |
| `internal/relay/server.go`、`internal/relay/clients.go` | 路由、独立资源、设备撤销、保留身份前缀、限速 |
| `internal/relay/client.go` | v2 业务认证分流，无 v1 自动降级 |
| `internal/relay/controller.go`、`internal/relay/contract/controller.go` | 配对装配和持久化暂停状态 |
| `internal/relay/client/share.go` | 可选本地配对与暂停/恢复控制接口 |
| `internal/relay/contract/sharecode.go` | 禁止导出私有 v2 凭据为口令 |
| `internal/relay/adapter/connector.go`、`internal/relay/adapter/connector_test.go` | v2 导入、独立撤销提示与终止错误分类 |
| `internal/relay/process/process.go`、`internal/relay/process/import_session.go` | 可选 IPC 能力、结果路由、公钥存储、挂起拨号取消、v2 导入 |
| `internal/relay/discovery/contract/types.go`、`internal/relay/discovery/names.go` | 可选发现能力 DTO 与 TXT |
| `internal/relay/discovery/cache.go`、`internal/relay/discovery/publisher.go` | 能力传播与更新判断 |
| `internal/model/model.go`、`internal/model/relay_test.go` | v2 节点、未确认标记、暂停与版本验证 |
| `internal/store/relay_share.go`、`internal/store/relay_known.go` | 暂停持久化；成功重连确认设备标记 |
| `internal/desktop/app.go`、`internal/desktop/relay_assembly.go` | 客户端注入与 sidecar 装配边界 |
| `internal/desktop/import_relay.go`、`internal/desktop/relay_history.go` | v2 面板、生命周期、已认证重连确认 |
| `internal/desktop/lan_discovery.go`、`internal/desktop/lan_discovery_view.go`、`internal/desktop/lan_discovery_test.go` | 新旧发现入口、未确认节点重试和授权范围提示验证 |
| `internal/desktop/lanshare.go`、`internal/desktop/lanshare_view.go` | 异步本地管理结果、暂停与管理页面 |
| `scripts/package-linux.sh`、`scripts/package-windows.sh`、`scripts/package-mac.sh` | 新依赖许可文件随包携带 |

参考且未修改：`internal/relay/server_test.go`、`server_lifecycle_test.go`、`controller_test.go` 的身份/会话/取消模式；`internal/relay/process/process_test.go` 的 sidecar 与严格拨号模式；`internal/store/store.go`、`relay_share_test.go` 的凭据和原子写入模式；`internal/desktop/lanshare_view_test.go`、`view_test.go` 的异步 UI、导入回滚和测试装配；`internal/desktop/component_boundaries_test.go` 的依赖与页面边界；`internal/relay/contract/protocol.go` 的业务额度；`internal/relay/tls.go`、`transport.go` 的证书钉住与原网络拨号；`internal/desktop/config.go` 的 UI 线程配置更新；`Makefile`、`scripts/buildtool/main.go`、`packaging/build-inputs.json`、`docs/plans/p5-relay-process-2026-11-27.md` 的构建与既有进程边界。

原有未跟踪 `go.work`、`go.work.sum` 保留不动，不纳入提交；所有验证显式使用 `GOWORK=off`。
