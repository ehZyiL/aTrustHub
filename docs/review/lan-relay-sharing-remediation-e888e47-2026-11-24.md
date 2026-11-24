## Related Files

- 新增：本文 `docs/lan-relay-sharing-remediation-e888e47-2026-11-24.md`。本次只形成处理方案，没有修改或提交应用源码。
- 审查依据：[原始 review](lan-relay-sharing-review-e888e47-2026-11-24.md)、[需求与 UI/UX 方案](lan-relay-sharing-plan-2026-11-24.md)、[详细实现规格](lan-relay-sharing-implementation-2026-11-24.md)。
- UI 与装配核对：`app.go`、`view.go`、`lanshare.go`、`lanshare_firewall_windows.go`、`platform_windows.go`。
- 服务端核对：`internal/relay/server.go`、`clients.go`、`protocol.go`、`errors.go`、`firewall.go`、`firewall_windows.go`。
- 会话与路由核对：`internal/vpn/manager.go`、`relay.go`、`resources.go`、`relay_share.go`。
- 存储与平台参考：`internal/store/relay_known.go`、`internal/wincapture/pipe_windows.go`。
- 现有测试入口：`lanshare_view_test.go`、`config_snapshot_test.go`、`internal/relay/server_test.go`、`internal/vpn/relay_e2e_test.go`、`internal/vpn/relay_share_test.go`。

除外层文档外，以上代码路径均相对 `aTrustHub/`。下文建议新增的测试和接口尚未实现；源码行号固定对应审查提交。

# 局域网分享：10 项 review 问题处理方案

日期：2026-11-24。分支：`feat/lan-relay-sharing`。审查基线：`e888e47d2a5c48ba7ac7b5c4bb68f824d10bdd11`。

交付目标：逐项修复 S1–S3、R1–R7，补上可复现的回归测试，通过后再合并。保留原 review 作为缺陷证据，修复提交引用相同编号。

## 1. 修复时必须保留的产品约束

1. 首次安装及旧配置升级默认关闭；打开面板、登录 VPN、B 导入节点都不触发 A 的共享监听。用户点击“开启共享”才保存启用意图。
2. 已启用时应用重启自动恢复同一共享身份、地址及端口；VPN 未连接则等待，不替用户登录、不改 AutoConnect、不自动换接入点。正常退出仅停止本次运行，不撤销长期口令。
3. “关闭共享”停止监听、取消待处理操作、终止业务流、撤销口令并持久化关闭；再次启动不恢复。再次手动开启生成新身份。
4. 共享整个所选接入点；不增加资源勾选或分享专用 ACL。底层继续执行接入点原有授权、停用规则、资源同步和撤权。
5. B 的未受管公网使用 B 的网络；已取得归属的 VPN 目标在断开、撤权或重启后不得自动改为直连。历史归属不能充当当前授权。首版仍只承诺 TCP 及已验证的代理使用方式。

## 2. 分工与交付顺序

| 批次 | 问题 | 建议责任范围 | 交付边界 |
| --- | --- | --- | --- |
| A：会话生命周期 | R1 [P1]、R6 [P2]、R7 [P2] | VPN/Manager 同事 | 结束事件及时处理，重试分类不变，重连后第一条更新可用 |
| B：服务端撤权 | R3 [P1]、R4 [P1]、R5 [P1] | relay 服务端同事 | 资源代次、租约和连接撤销统一，旧流关闭，新授权流可用 |
| C：历史与 UI | R2 [P1]、S1 [P1] | Store 与桌面 UI 同事 | 历史归属跨重启保留，后台持久化不触碰 UI 配置 |
| D：Windows 防火墙 | S2 [P2]、S3 [P2] | Windows 平台同事 | 普通用户可授权，规则可读回、可清理、可恢复 |

A/B/C 都是合并前优先处理项，可以分工开发；A/C 同时修改 Manager/快照回调时先对齐接口。D 依赖受限提权执行入口，再接完整生命周期。建议按以上 4 个批次提交；每个批次包含回归测试，不做仅改文案或屏蔽失败测试的提交。

## 3. Standards 各项处理

### S1 [P1] 后台回调改写 UI 配置

修改入口：[lanshare.go:781](/home/ehzyil/Projects/Learn/easy-connect/aTrustHub/lanshare.go:781)、[app.go:64](/home/ehzyil/Projects/Learn/easy-connect/aTrustHub/app.go:64)。与 R2 一起交付。

处理方案：

1. `saveRelaySnapshot` 只更新 Store、持久化历史并通知 Manager，不在后台调用 `a.setConfig`，也不直接写 UI 状态。
2. 复用应用现有“后台投递、UI 线程消费”的模式。配置变更通知必须在常规 UI 更新入口消费，不能只在打开“局域网分享”面板时处理；可以合并重复刷新通知。
3. UI 回调真正执行时读取最新 `Store.Config()` 再调用 `setConfig`，避免排队的旧配置覆盖后来已保存的编辑；未保存草稿继续保留在独立草稿结构。
4. 若使用 `win.Update`，不得持有 Store/Manager 锁等待 UI。窗口未初始化或已销毁时，保留 Store 状态并由后续初始化读取，不回退为在工作线程执行 UI 写入。

验收：将原 `TestReviewRelaySnapshotConfigRace` 转为仓库回归；通过可控制的 UI 调度器模拟首次快照、界面读取及用户保存交错，`-race` 无报告，用户编辑不被覆盖；窗口关闭后后台回调能退出，面板未打开时配置仍同步。

### S2 [P2] Windows 防火墙没有实际提权

修改入口：[internal/relay/firewall_windows.go:45](/home/ehzyil/Projects/Learn/easy-connect/aTrustHub/internal/relay/firewall_windows.go:45)、[lanshare_firewall_windows.go:89](/home/ehzyil/Projects/Learn/easy-connect/aTrustHub/lanshare_firewall_windows.go:89)。参考项目现有 `internal/wincapture/pipe_windows.go` 的 RunAs/受限助手模式。

处理方案：

1. 由平台适配层启动需要 UAC 授权的受限 helper。仅开放创建、查询、删除本应用防火墙规则三种结构化操作；不把整个 GUI 改成管理员运行，不提供任意命令执行入口。
2. helper 独立验证调用方、程序绝对路径、自有规则 ID、TCP 端口、允许的网络 profile 和选定接口的实际子网。参数通过结构化 IPC 或正确的系统参数编码传递，不把路径和名称拼成 shell 脚本。
3. 创建/删除后读回完整规则或确认不存在；核对程序、方向、协议、端口、profile、远端范围，不能只查到同名规则就报成功。查询失败与“规则不存在”必须分开。
4. 区分取消 UAC、权限失败、执行超时、创建成功但读回失败。取消或超时不能假定系统一定没改动，保留待核对 journal；UI 不宣称已放行。

验收：普通用户启动 Windows 实机，分别接受/取消授权；程序位于含空格/中文的目录仍可操作；规则范围精确，未扩大到 Public/任意地址；创建和删除均验证结果。接口子网必须取实际掩码，不能继续无条件假定 `/24`，作为本次最小范围校验一并处理。

### S3 [P2] 防火墙 journal 缺少生命周期闭环

修改入口：[lanshare.go:152](/home/ehzyil/Projects/Learn/easy-connect/aTrustHub/lanshare.go:152)、[lanshare.go:724](/home/ehzyil/Projects/Learn/easy-connect/aTrustHub/lanshare.go:724)、`lanshare_firewall_windows.go`、`internal/relay/firewall.go`。依赖 S2。

处理方案：

1. 把规则管理集中到应用的平台协调层，订阅共享运行实例的启动/停止；relay 核心不导入 UI/平台业务。所有创建、清理和 journal 写入串行处理，防止多个旧 journal 副本相互覆盖。
2. 统一覆盖手动关闭、正常退出、源断开/暂停、删除共享接入点、恢复失败及启动遗留恢复。先终止监听和流量，再清理本应用拥有的规则。
3. 正常退出和源暂停保留 Enabled、共享身份及既有授权范围；显式关闭保存 Enabled=false 并撤销身份。防火墙清理失败不得阻止业务流停止，也不得谎报清理完成。
4. 启动先核对遗留 journal：无效规则清理，仍被授权且与恢复实例完全一致的规则可核对后复用或重建。需要新授权或范围变化时显示待处理；不默默扩大原授权，不把监听成功标成已通过防火墙验证。
5. 每次规则操作绑定运行实例/operation ID。用户关闭后，迟到的创建即使成功也必须转入删除流程；只有确认系统状态后才移除 journal 项。

建议生命周期验收：

| 事件 | 共享意图/身份 | 规则处理 |
| --- | --- | --- |
| 用户关闭/删除共享接入点 | 关闭并撤销 | 关闭业务后清理，失败保留待处理 |
| 正常退出 | 保留 | 有限时间内清理；未完成留 journal |
| 源断开、地址失效、恢复失败 | 保留，等待原前置条件 | 清理失效运行实例规则 |
| 崩溃后重启 | 按已保存意图恢复 | 先核对旧记录，再恢复或提示授权 |
| 关闭期间收到创建成功回调 | 维持关闭 | 删除迟到规则，不能重新变成运行中 |

实机验收还要覆盖拒绝清理授权、journal 保存失败和“创建成功但未确认即崩溃”。UAC 无法完成时应明确显示待清理，不能承诺退出必然删除。

## 4. Spec 各项处理

### R1 [P1] 更新消费阻塞会话结束监听

修改入口：[internal/vpn/manager.go:786](/home/ehzyil/Projects/Learn/easy-connect/aTrustHub/internal/vpn/manager.go:786)、[internal/vpn/relay.go:231](/home/ehzyil/Projects/Learn/easy-connect/aTrustHub/internal/vpn/relay.go:231)。与 R6/R7 一起交付。

处理方案：

1. 推荐把当前串行 `consumeUpdates → watch` 改为会话监视循环，同时 select `Updates`、`Done` 和该会话的取消信号。兼容未实现 updater/watcher 的原 VPN Session；Updates 关闭只停止更新消费，不能跳过 Done。
2. 会话监听使用独立运行上下文，不能复用连接阶段即将 defer cancel 的登录上下文。断开、删除、替换及 Manager 关闭都取消对应监听，不靠 30 秒轮询退出。
3. 结束处理仍在 Manager 锁内校验 point/generation/session，再更新状态、保留 Known 和决定重试；网络 Close、等待 goroutine 均放到锁外。晚到旧会话事件不能影响新会话。
4. 将 `relaySession` 的“一次性发出终止原因”和“幂等完成清理”分开。`fail` 后再 `Close` 仍需完成清理，不能因 closed 已置位而遗漏；heartbeat 自己不能等待包含自己的 WaitGroup。
5. Updates 只能由发送方在确认发送结束后关闭。确保 Done/Err 先后关系明确，保留首个终止原因；取消时阻塞发送可退出，不发生重复关闭或 send-after-close。

验收：真实 `relaySession.fail` 触发后，不依赖健康探测或轮询，Manager 及时离开 Online；控制通道没更新也能断开。覆盖人工 Close 与 fail 并发、更新通道单独关闭、删除/退出、可重试失联及终止错误不重试；无死锁与残留监听 goroutine。

### R2 [P1] 当前快照覆盖磁盘历史

修改入口：[internal/store/relay_known.go:95](/home/ehzyil/Projects/Learn/easy-connect/aTrustHub/internal/store/relay_known.go:95)、[lanshare.go:781](/home/ehzyil/Projects/Learn/easy-connect/aTrustHub/lanshare.go:781)。与 S1 一起交付。

处理方案：

1. 将保存改为受同步保护的“读旧历史 → 校验身份 → 合并归属 → 校验容量 → 原子写入”。同一 point 的并发保存及删除必须互斥；以“旧磁盘历史 ∪ 新已验证快照”保存，空快照不清空历史。
2. 复用 `internal/vpn/resources.go:rememberResources` 的归属合并语义；若 Store 需要复用，抽到不依赖 Manager 的小型公共层，避免引入反向依赖。合并结果只供 Known 使用，Current 始终来自最新授权快照。
3. 快照回调携带已认证源身份，保存时核对 point 仍存在且 share ID/证书指纹一致；不能仅重新读取可变配置便假定快照属于它。删除/重导入后的迟到旧回调不应重建缓存或误标初始化。
4. 完成顺序：持久化历史并集 → 成功持久化 HistoryInitialized → 发布当前授权；可先增加保护性 Known。任一步失败拒绝新授权发布，已有历史不被覆盖；UI 刷新按 S1 调度。
5. 归一化并去重，遵守现有 4 MiB 上限；不按时间/条数静默裁剪。缓存损坏、来源不符或超限时保留证据并启用保护。若历史已丢失，仅取回当前快照无法证明恢复了旧归属，不能据此自动清除保护。
6. 恢复可信历史后按所有 relay 节点重新计算保护状态：只能解除已修复节点的自动连接阻断；任一节点仍不可信，全局未知目标保护继续生效。删除节点或显式解除保护沿用原方案的用户知情流程，不在后台自动执行。

验收：A 发布目标 → B 保存 → A 撤回 → B 保存空/较小快照 → B 重启且 A 不可达，旧目标仍属于 Known、不可直连，也不获得 Current 授权；覆盖重复快照不增长、并发合并不丢项、来源切换/删除竞态、坏缓存/超限/写入失败，以及两个节点仅修复其中一个的门控。

### R3 [P1] 资源变化后永久拒绝新连接

修改入口：[internal/relay/server.go:623](/home/ehzyil/Projects/Learn/easy-connect/aTrustHub/internal/relay/server.go:623)、[internal/relay/clients.go:235](/home/ehzyil/Projects/Learn/easy-connect/aTrustHub/internal/relay/clients.go:235)。必须与 R4 联合设计。

处理方案：

1. 将连接表的“永久关闭”和“撤销旧资源代次连接”分为两种操作。`Stop/Close` 为不可逆终态；资源变更只淘汰旧代次，不设置永久 stopped。
2. 为连接预留记录关联资源代次及客户端生命周期。登记时原子校验 share 仍运行、请求代次仍为当前、客户端仍有效，避免“检查通过 → 撤权 → 迟到登记”的空隙。
3. 切代时使旧代次立即失效，取消该代次待处理的拨号/DNS，取出旧连接后在锁外关闭双方；晚返回的上游连接直接关闭。新代次发布后接受相符的新请求。
4. 保留控制租约，让 B 刷新资源后继续使用。禁止用“stopAll 后把 stopped 改回 false”修补，否则 Stop 与更新竞争可能重新打开已关闭的共享。

验收：每次更新都关闭旧业务流，正确新版本 CONNECT 成功；连续更新可重复使用；Stop 与资源更新同时发生不会复活共享；拨号完成晚于切代时不泄漏连接或槽位。

### R4 [P1] 快照缓存让撤权变更不可见

修改入口：[internal/relay/server.go:574](/home/ehzyil/Projects/Learn/easy-connect/aTrustHub/internal/relay/server.go:574)、[internal/relay/server.go:615](/home/ehzyil/Projects/Learn/easy-connect/aTrustHub/internal/relay/server.go:615)。与 R3 同批交付。

处理方案：

1. 保存上一份“已提交、已用于授权”的 epoch/revision 作为比较基准；读取新源快照后与它比较。不能收到 Changes 后重新读一次源并把该结果当作 before。
2. 所有快照变更走一个提交入口：触发新快照读取、验证、使旧代次失效、撤销旧操作/连接、发布新授权。GET/Status 的缓存刷新发现版本变化时也走这个入口，不能绕开撤权副作用。
3. 资源代次切换与连接登记有共同的同步边界；旧登记失效与新版本可见必须一致。实际连接关闭放锁外，但失效标记/取消信号不能晚于新授权的可见性。
4. Changes 可合并，提交最终源版本；快照获取失败时停止新授权业务并保守结束旧代次工作，保留身份、控制状态与归属，不继续用可能已撤销的旧权限。源终止与显式 Stop 不能被晚到刷新覆盖。

验收：确定性测试分别覆盖缓存仍新鲜、已过期、被 Status/Resources 抢先刷新三条路径；真正移除旧目标后，存量连接关闭，仍授权的新连接可建立。覆盖连续/合并变更、读取失败恢复及 Stop 竞态，测试用可控时钟/事件而非随机 sleep。

### R5 [P1] 客户端过期只删除记录，没有撤销业务

修改入口：[internal/relay/clients.go:127](/home/ehzyil/Projects/Learn/easy-connect/aTrustHub/internal/relay/clients.go:127)、`internal/relay/server.go` 的认证、CONNECT、DNS 和 DELETE 路径。

处理方案：

1. 为每个客户端租约增加可取消生命周期，并集中撤销操作。到期、主动删除、同实例重认证替换、共享终止全部使用同一撤销流程，旧 token 与新租约严格分离。
2. registry 锁内标记失效并移出索引，锁外取消该客户端的待处理拨号/DNS、关闭其连接、释放计数。`lookup/count/create/sweep` 所有过期入口都要产生相同清理效果。
3. CONNECT 从查到 token 到预留、拨号、attach、返回成功都绑定同一个仍有效的租约/代次；撤销与登记互斥。续租也重新验证当前索引指向同一租约，不能复活刚过期或被替换的对象。
4. 为 `connEntry` 增加不可逆 closed 状态。close 后晚到的 attach 立即关闭传入连接；关闭网络连接放在锁外，保证重复撤销及 handler release 不重复扣计数。
5. 主动 sweep 保证闲置客户端到期后也清理，定时精度与租约一致；使用主机单调时钟，不信任客户端时间。测试注入时钟及可控制拨号完成顺序。

验收：真实 CONNECT 建立后让租约到期，旧流断开、在途拨号取消、晚到连接被关闭、连接槽位归还；同实例重认证立即结束旧 token 的流；续租/到期竞争不能复活旧会话，其他客户端连接不受影响。

### R6 [P2] 友好错误丢失类型和重试语义

修改入口：[internal/vpn/relay.go:113](/home/ehzyil/Projects/Learn/easy-connect/aTrustHub/internal/vpn/relay.go:113)、`RelayReconnectable`。与 R1 一起交付。

处理方案：

1. 推荐增加带 `Unwrap()` 的显示错误包装，`Error()` 返回友好文案，原错误作为 cause；保留原 `relay.Error` 的 Code、Status、Retryable、RequestID。不再转换成裸 `errors.New`。
2. 重连判断继续根据结构化错误分类，不能匹配中文文本。`share_closed`、无效凭据、协议不兼容等终止原因不进入自动重试；暂时网络失败按既有有界策略处理。
3. `session_expired` 只在现有约定允许的范围内尝试有限次重认证；用尽后作为终止原因，不靠反复重连突破预算。单目标授权拒绝不应因文案包装变成全节点重登。
4. 覆盖初次连接、heartbeat、资源刷新和业务拨号所有文案转换路径；不修改共享原错误对象，确保并发读取安全。

验收：全部协议错误经真实 `friendlyRelayError` 后，`errors.As` 仍取得原类型及完整字段；终止/瞬时分类符合策略。通过真实 connector/heartbeat → Manager 路径验证，不只测试手工构造的假 Session。

### R7 [P2] 更新序号跨会话残留

修改入口：[internal/vpn/manager.go:811](/home/ehzyil/Projects/Learn/easy-connect/aTrustHub/internal/vpn/manager.go:811)，以及成功登记 `cur.sess` 的代码块。与 R1 一起交付。

处理方案：

1. 每次成功安装新的 session/generation 时，在 Manager 锁内把 endpoint 的 `updateSeq` 置为 0，与 session 指针替换处于同一临界区。
2. 更新仍按 point、generation、session 身份与严格递增 Sequence 联合判断；先验证身份，再比较/写入序号。不能在每次收到事件时重置序号。
3. 旧会话再大的序号也不能更新新会话游标或资源；同会话重复、倒序更新继续被拒绝。无需改变分享协议或把序号写入磁盘。

验收：旧会话接受 seq=2 → 断开 → 新会话首次 seq=2 被接受；旧 generation 晚到 seq=100 被拒绝且不污染游标；新会话后续 seq=3 正常，同会话重复 seq=2 被丢弃。

## 5. 测试交付与合并门槛

先把 review 中 8 个临时 overlay 复现移入仓库，作为相应修复批次的永久回归；原文件位于 `/tmp`，不能作为交付依赖。S2/S3 追加平台单元测试和 Windows 实机记录。

建议测试落点：会话问题进入 `internal/vpn/manager_test.go` 及 relay 测试；服务端问题进入 `internal/relay/server_test.go` 及客户端生命周期测试；历史写入新增 `internal/store/relay_known_test.go`；UI 并发进入 `config_snapshot_test.go`/`lanshare_view_test.go`；Windows 操作通过可替换执行器/平台协调器测试，再实机验证。

修复后从 `aTrustHub/` 执行：

```sh
go test ./...
go test -race ./internal/relay ./internal/store ./internal/vpn
go test -race . -run 'Relay|LANShare|Config' -count=1
go build ./...
go vet ./...
git diff --check
```

仅列验收命令，不表示本次已执行修复后测试。此前基线检查通过但临时复现失败，不能据此前基线宣称缺陷已解决。

跨模块必须验证以下完整场景：

1. 共享首次关闭 → 用户开启 → 正常退出 → 重启恢复原身份；VPN 未连接显示等待 → 原 VPN 登录后恢复；用户关闭后重启不恢复。
2. A 资源撤回/原停用规则变化 → 旧流终止 → B 刷新 → 当前授权流可建立；A 断开/退出时 B 状态及时离开 Online，已知目标不直连。
3. B 同步撤回后重启，A 离线：Known 仍阻止旧目标直连；普通未受管公网继续从 B 出口。历史不可信时按既有保护策略明确提示，不伪报完全就绪。
4. Windows 普通用户授权、拒绝、清理失败、源暂停、正常退出、强杀及启动恢复；记录实际规则属性和 journal 最终状态，交叉编译通过不能替代实机证据。
5. 再跑原有非 relay VPN、统一代理和系统代理恢复回归；不额外扩大到透明全机接管、UDP 或新资源维度。

完成定义：10 项都有对应修复提交与回归证据；P1 路由/撤权/竞态回归通过；Windows 两项有普通权限实机结果。二维码渲染、可选剪贴板识别、首次托盘提示等原 review 已说明的交付缺口单独跟踪，本清单不把它们认定为已完成。
