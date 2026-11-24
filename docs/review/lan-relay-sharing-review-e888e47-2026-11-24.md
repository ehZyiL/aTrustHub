# feat/lan-relay-sharing 代码审查

## Related Files

- 新增：本文 `docs/lan-relay-sharing-review-e888e47-2026-11-24.md`。没有修改或提交应用仓库文件。
- 审查依据：工作区原始 `docs/lan-relay-sharing-implementation-2026-11-24.md`、`docs/lan-relay-sharing-plan-2026-11-24.md`、本次会话确认的产品要求、用户提供的 AGENTS 执行规范及 `/home/ehzyil/.agents/skills/code-review/SKILL.md`。
- 规范和实现说明：应用仓库 `go.mod`、`docs/README.md`、`docs/design/architecture.md`、`docs/design/networking.md`、`docs/design/lan-relay-sharing-implementation-2026-11-24.md`、`docs/design/lan-relay-sharing-plan-2026-11-24.md`。
- 应用装配/UI：`app.go`、`view.go`、`lanshare.go`、`import_relay.go`、`lanshare_firewall_windows.go`、`platform_windows.go`；测试参考 `view_test.go`、`config_snapshot_test.go`、`lanshare_view_test.go`。
- 模型：`internal/model/model.go`、`internal/model/localapp.go`。
- 存储：`internal/store/store.go`、`internal/store/session_secrets.go`、`internal/store/relay_share.go`、`internal/store/relay_known.go`、`internal/store/relay_share_test.go`。
- 中继：`internal/relay/controller.go`、`server.go`、`clients.go`、`client.go`、`protocol.go`、`tls.go`、`transport.go`、`errors.go`、`firewall.go`、`firewall_windows.go`、`firewall_other.go`；测试参考 `internal/relay/server_test.go`。
- VPN 集成：`internal/vpn/manager.go`、`relay.go`、`relay_share.go`、`relay_snapshot.go`、`routing.go`、`localdial.go`、`easyconnect.go`、`zju.go`、`resources.go`；测试参考 `internal/vpn/manager_test.go`、`relay_share_test.go`、`relay_e2e_test.go`。
- 临时复现文件：`/tmp/connect-hub-review-server-e888e47_test.go`、`/tmp/connect-hub-review-server-e888e47-overlay.json`、`/tmp/lan-relay-spec-review-EXgY1b/review_test.go`、`/tmp/lan-relay-spec-review-EXgY1b/overlay.json`、`/tmp/lan-review-standards-race_test.go`、`/tmp/lan-review-standards-overlay.json`。均通过 Go overlay 注入，不写入应用工作树；这些临时路径仅适用于当前工作区。

除外层原始方案、技能和临时文件外，上述代码路径均相对 `aTrustHub/`。本次未使用假想的 Windows 文件路径作为实际规范来源。

## 范围与结论

- 日期：2026-11-24。
- 审查分支：`feat/lan-relay-sharing`，HEAD `e888e47d2a5c48ba7ac7b5c4bb68f824d10bdd11`。
- 固定比较点：`dev-main` / `f3f7cf92a52f218cb03540d70c3b1cf01594face`；这是该分支的 merge-base，也是设计文档的原始源码基线。
- 比较：`git diff f3f7cf92a52f...HEAD`，17 个提交，55 个变更文件，新增 13085 行、删除 44 行。
- 方式：Standards 与 Spec 两轴独立审查，聚合时保持分开；针对发现增加临时复现，不实施修复。

**建议暂缓合并。** 基础流程和既有测试已覆盖较多行为，但本次确认 10 项问题：Standards 3 项，Spec 7 项。其中 8 项有本地定点复现，另外 2 项 Windows 防火墙问题有明确调用链证据、尚无 Windows 实机验证。

首次默认关闭、用户开启后重启恢复、明确关闭后不恢复、按整个接入点共享是固定产品要求。接入点资源快照仍用于底层授权/分流，不能因产品不提供资源勾选而忽略撤权及历史归属。

## Standards

### S1 [P1] 首次快照的后台回调直接改写 UI 配置

位置：[lanshare.go:806](/home/ehzyil/Projects/Learn/easy-connect/aTrustHub/lanshare.go:806)，关联 `app.go:64–67`、`:986–989`、`lanshare.go:365–366`。

`saveRelaySnapshot` 由后台连接/心跳调用。首次设置 HistoryInitialized 后，它执行 `a.setConfig(next)`，会替换 `a.cfg`。虽然 setConfig 对写方加了 cfgMu 锁，实际 UI 读取（例如 pointLabel）不取这个锁，因此仍然发生数据竞争。代码注释明确规定 cfg 由 UI 线程读写，后台读取须走独立快照；新增路径违反这个已有线程约定。

触发：B 首次连接新导入的 relay，同时 UI 渲染接入点/共享面板。真实 `saveRelaySnapshot` 与真实 `pointLabel` 并发的 race 测试报告 3 条 DATA RACE，写栈落在 `app.go:988 ← lanshare.go:807`。可能观察到撕裂配置或与 UI 编辑互相覆盖。

修复方向：后台仅修改 Store，配置发布通过 UI 调度执行；保持所有 UI 配置写入的线程所有权，并增加首次同步与渲染并发的 race 回归。

### S2 [P2] Windows 的“允许局域网连接”没有提权路径

位置：[internal/relay/firewall_windows.go:45](/home/ehzyil/Projects/Learn/easy-connect/aTrustHub/internal/relay/firewall_windows.go:45)，调用方 `lanshare_firewall_windows.go:89–99`。

UI 显示“正在请求系统授权”，但实际只是 `exec.Command("netsh", ...)`，调用方和命令内部都没有 RunAs/提升令牌步骤。正常以普通用户启动 GUI 时，不会弹出授权流程，创建规则直接因权限失败；删除规则也存在相同问题。项目已有 `platform_windows.go` / `internal/wincapture/pipe_windows.go` 的提权模式可参考。

修复方向：复用受限的现有提权模式执行创建/删除，并正确传递取消授权与读回失败；用普通权限启动的 Windows 实机验证。该项为静态调用链证据，当前 Linux 环境未执行 netsh。

### S3 [P2] 防火墙 journal 未接入退出和启动恢复

位置：[lanshare.go:152](/home/ehzyil/Projects/Learn/easy-connect/aTrustHub/lanshare.go:152)，对照唯一 UI 清理调用 `lanshare.go:724`。

只有 UI 的 disableLANShare 成功分支会调用 cleanupLanShareFirewall。正常退出的 shutdownLANShare、启动 setup/resume、源失效暂停及删除共享接入点直接 Disable，都没有接到规则清理。即使用户通过管理员运行成功创建了规则，这些路径仍会留下入站规则与 journal。进程结束会关闭监听，不会自动删除防火墙规则。

修复方向：把自有规则清理接到统一生命周期，在恢复监听前处理遗留 journal；如要自动重建规则，仅复用原用户授权范围。该项违反方案 §12 的停止清理/崩溃恢复契约，当前无 Windows 实机结果。

## Spec

### R1 [P1] 资源更新循环阻塞断线监听，失效节点仍为 Online

位置：[internal/vpn/manager.go:786](/home/ehzyil/Projects/Learn/easy-connect/aTrustHub/internal/vpn/manager.go:786)，关联 `internal/vpn/relay.go:231–246`、`:385–401`。

connect 先同步调用 consumeUpdates，再调用 watch。健康 relay 的 Updates 是持续通道，consumeUpdates 不返回；真实 relaySession.fail 虽关闭 Done，却不关闭 Updates，而且后续 Close 会因 closed 标记提前返回。30 秒轮询只检查 Manager 自己仍保留的 Online/session 身份，无法打破这个依赖。

触发：主机失联、撤销或心跳终止，Session Done 已关闭，B 仍显示 Online，watch 不执行，错误和重连流程无法及时发生。真实 relaySession 调 fail 的定点测试已复现。违反原方案 §9.2 的 SessionWatcher.Done/Err 传播要求。

修复方向：并发消费更新与会话结束，或让统一 select 同时监测 Done；保证失败和主动 Close 都能完成发送端清理与通道退出。

### R2 [P1] 历史缓存被当前快照覆盖，重启后旧 VPN 目标改走直连

位置：[internal/store/relay_known.go:95](/home/ehzyil/Projects/Learn/easy-connect/aTrustHub/internal/store/relay_known.go:95)，调用点 `lanshare.go:790`。

SaveRelayKnown 直接把传入的当前 resources 写入缓存，没有合并以前的归属。运行中 Manager 使用 rememberResources，因此当时看似有保护；但磁盘只留下最后一版。

触发：A 撤回一个已发布目标 → B 同步新快照 → B 重启且 A 不可达。旧目标从 Known 消失，会进入普通 direct 分支。定点测试先存公司网段，再存撤回后的空快照，Load/Seed 新 Manager 后，`10.5.1.2:443` 的决策确实为 `Action:direct`。违反原方案 §10.2“不自动截断历史规则”的约定。

修复方向：在当前授权发布前持久化历史归属并集，校验来源身份并控制容量；缓存只提供 Known，不能将旧授权恢复成 Current。

### R3 [P1] 资源更新永久禁止后续新隧道

位置：[internal/relay/server.go:623](/home/ehzyil/Projects/Learn/easy-connect/aTrustHub/internal/relay/server.go:623)，关联 `internal/relay/clients.go:235–237`。

watchChanges 为结束旧流调用 conns.stopAll；这个操作同时永久设置 stopped=true。此后即使 B 获得正确的新 epoch/revision，所有新 CONNECT 仍被登记表拒绝为 share_closed。控制通道和 UI 仍可显示正常，需要关闭再开启共享才能恢复。

复现：缓存中有旧快照时更新资源，确认处理后 Status 成功，新授权 CONNECT 返回 `share_closed: 分享已关闭`。违反 §8“资源变化后发布新快照、客户端恢复业务”的契约。

修复方向：区分永久 Stop 和仅关闭当前代次流；结束旧流后允许新版本请求登记，同时保留撤销竞态保护。

### R4 [P1] 缓存超过 200ms 后，资源撤销不能关闭已有连接

位置：[internal/relay/server.go:615](/home/ehzyil/Projects/Learn/easy-connect/aTrustHub/internal/relay/server.go:615)。

收到 Changes 后才调用 snapshot 作为 before。若 200ms 缓存已经过期，这次调用直接读取新资源；随后 invalidate 再读取的 after 也是新资源，比较认为没有变化，跳过存量连接清理。

触发：普通长连接建立后超过缓存期，再撤回其权限。定点测试使缓存过期、从源规则中移除该目标，并等到服务端已读取新代次，原连接仍能双向传输。违反 §8“资源改变取消旧业务流”。这与 R3 是两个独立分支，单改 stopAll 的行为不能消除本项。

修复方向：保存上一份已发布的代次作为比较基准，或为可信的变更通知执行正确的代次切换；不要把事件发生后的重新读取当成旧快照。

### R5 [P1] 客户端租约过期后，既有 VPN 隧道仍可持续使用

位置：[internal/relay/clients.go:127](/home/ehzyil/Projects/Learn/easy-connect/aTrustHub/internal/relay/clients.go:127)。

expireLocked 只从 byToken/byID 删除认证记录，未调用连接表关闭对应 token 的业务连接，也没有取消该客户端待处理操作。sweep、count 和 lookup 都可以触发这种仅删登记的过期处理。

复现：先建立真实 TLS CONNECT，令其租约过期并执行生产 ActiveClients 清理；活跃客户端数已为 0，旧连接仍可正常 ping/pong。缺少控制会话的长连接可以继续占用 VPN 和连接槽位。违反原方案 §9.3“A 也清理过期客户端及其连接”。

修复方向：租约失效与重认证替换时，统一撤销对应客户端并在锁外关闭它的存量流/取消待处理拨号，确保清理与新登记互斥。

### R6 [P2] 友好文案转换丢弃终止错误类型

位置：[internal/vpn/relay.go:113](/home/ehzyil/Projects/Learn/easy-connect/aTrustHub/internal/vpn/relay.go:113)。

friendlyRelayError 把类型化 relay.Error 转为 errors.New，丢失 Code。RelayReconnectable 使用 errors.As 判断终止原因，经过真实文案转换后无法识别 share_closed / invalid_credentials / protocol_unsupported，继而把终止错误判成可重连。watch 的问题修好后，本项仍会破坏重试策略。

复现：`RelayReconnectable(friendlyRelayError(CodeShareClosed))` 返回 true。现有相关测试使用尚未转换的类型化假错误，未覆盖该路径。违反原方案 §9.3 类型化终止原因和手动恢复要求。

修复方向：保留可 unwrap 的原错误或复制其类型并只替换 Message；显示文案不改变重试语义。

### R7 [P2] 新会话沿用旧 updateSeq，资源更新被丢弃

位置：[internal/vpn/manager.go:811](/home/ehzyil/Projects/Learn/easy-connect/aTrustHub/internal/vpn/manager.go:811)。

endpoint.updateSeq 跨会话保留，成功 connect/换代没有重置；每个新 relaySession 又从 seq=1 起步。旧会话接受过 seq=2 后，新会话的第一次 seq=2 更新会被拒绝。如果后续没有更多更新，Manager 将一直使用重连时的旧快照，新资源无法访问、撤回状态也不能正确呈现。

定点测试以新 generation/session 加入第一条 seq=2 更新，保留旧 updateSeq=2，确实被丢弃。违反原方案 §9.2 按 endpoint、generation、session 和递增序号联合保护更新的约定。

修复方向：在会话成功登记或代次切换时重置序号，并补完整的“更新 → 重连 → 首次更新”回归。

## 验证

在 `aTrustHub/` 执行的既有检查均通过：

```text
go test ./internal/model ./internal/store ./internal/relay ./internal/routing ./internal/proxy ./internal/vpn
go test ./...
go test -race ./internal/relay ./internal/store
go test -race ./internal/vpn -run 'Relay|Headless|Seed' -count=1
go build ./...
go vet ./...
git diff --check f3f7cf92a52f...HEAD
```

特别说明：本次 `go test ./...` 的 workeripc 测试也通过，与分支文档记录的历史失败不同，以本次结果为准。

补充复现命令如下，它们**预期失败，用于证明缺陷**，不表示已有测试突然回归；临时 overlay 不改变原测试文件或生产代码：

```text
go test -overlay=/tmp/connect-hub-review-server-e888e47-overlay.json ./internal/relay -run '^TestReview' -count=1 -v
go test -overlay=/tmp/lan-relay-spec-review-EXgY1b/overlay.json ./internal/vpn -run '^TestReview' -count=1 -v
go test -overlay=/tmp/lan-review-standards-overlay.json -race . -run '^TestReviewRelaySnapshotConfigRace$' -count=1
```

| 复现测试 | 对应问题 | 实际结果 |
| --- | --- | --- |
| TestReviewResourceChangeAllowsNewTunnels | R3 | 正确新版本 CONNECT 返回 share_closed |
| TestReviewResourceChangeClosesOldTunnelsAfterCacheExpiry | R4 | 源已移除目标权限，旧流仍可读写 |
| TestReviewExpiredLeaseClosesExistingTunnel | R5 | 活跃租约已清除，旧流仍可读写 |
| TestReviewUpdaterMustNotBlockWatcher | R1 | 真实 relaySession.fail 后 Manager 仍为 Online |
| TestReviewHistoryRetainsWithdrawnOwnershipAcrossRestart | R2 | 已撤回历史目标在重载后变成 direct |
| TestReviewFriendlyTerminalErrorRetainsClassification | R6 | share_closed 经文案转换后可重连 |
| TestReviewNewSessionUpdateSequenceStartsFresh | R7 | 新代次首次更新被旧序号丢弃 |
| TestReviewRelaySnapshotConfigRace | S1 | 真实生产回调与 UI 读取产生 3 条 DATA RACE |

S2/S3 的修复需要另做 Windows 普通用户启动、授权拒绝、正常退出、源断开与崩溃重启的实机验收；本次未修改系统代理、防火墙或真实 VPN。

## 交付限制

分支文档已承认二维码渲染、可选剪贴板识别、首次隐藏托盘提示未实现；跨机器平台验收也未完成。这些不是本次新发现的 10 项代码缺陷，但不应把文档的“T01–T10 已实现”理解为全部原始验收条件已经满足。

建议各问题分别修复并补上对应回归，尤其 R3/R4 需要同时验证“撤权关闭旧流”和“新版本仍能新建流”。R1 修复后还应验证 R6 的真实终止原因不进入自动重试。

Standards：3 项，最严重为后台改写 UI 配置的数据竞争。Spec：7 项，包含已知 VPN 目标直连、撤权残留连接和共享失效等 P1 问题。两个维度均存在合并前需处理的问题。
