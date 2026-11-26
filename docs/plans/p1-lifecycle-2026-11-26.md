# P1 分享与发现生命周期记录

日期：2026-11-26。对应 [分阶段方案](component-boundaries-2026-11-26.md)；优化前数据见 [P0](p0-baseline-2026-11-26.md)。

## 已实现行为

- `NewController`、`NewPublisher`、发现装配只构造对象，默认没有功能专用循环、监听或发布任务。
- 分享在显式 Enable 或恢复已有 Enabled 意图时创建监督任务；Disable、取消首次启动和 Shutdown 取消任务并等待退出。操作串行，停止可取消正在获取的 VPN Source；首次启动取消或失败时释放部分资源，避免下一次启用继承正在撤销的身份。
- 发布器由 Set 启动，Clear 撤销公告并使协调任务退出；再次 Set 可启动。重复关闭与并发 Set/Clear 有回归测试。后端超时之后返回的注册句柄由原生产者负责关闭，不会因为收集任务已退出而丢失所有权。
- 发现协调从永久两秒 ticker 改为通知合并后的短期任务。页面搜索提示使用最多五秒的一次性截止时间，关闭页面即取消。
- 浏览 Close 取消启动、等待过期任务、关闭会话并清空缓存；应用 Shutdown 为最终状态，晚到的页面打开不能再启动。缓存写入与代次切换在同一锁下完成，旧快照不能进入新页面。
- 关闭发现页面不会停止分享；发现偏好关闭不会撤销分享口令。既有严格会话/资源版本、防火墙恢复、历史内网归属语义保留。

Relay 仍在 Hub 进程中。独立 relay 可执行程序属于 P5，P1 不声称已经隔离其代码或运行时内存。

## 自动化验证

Windows Go 1.27.4，`GOWORK=off`：

- `go test ./... -count=1` 全部通过；原始输出在 `build/p1-tests-windows.log`。
- 新增跨装配回归 `TestUnusedSharingHasNoBackgroundTasks` 从优化前稳定失败（3 个循环）变为通过。
- `TestOptionalResourcesStopAndRestartTenTimes` 连续十轮分享、发布、浏览、停用，检查功能任务在一秒内结束、无活动公告、无残留候选，以及关闭页面不影响分享。
- controller/discovery 包覆盖 worker 退出、重复开关、并发启停、获取 Source 中取消、启动返回部分资源时关闭、最终关闭后拒绝再启动；相关定向测试重复三次通过。
- 统一入口构建 Windows Hub、Worker、网络助手成功；Worker IPC 生成一致性检查通过。

WSL Debian，Go 1.27.4、CGO/gcc：

```text
GOWORK=off go test -race ./internal/relay/... -count=1
GOWORK=off go test -race . -run 'Test(UnusedSharing|OptionalResources|IdleDiscovery|Acceptance)' -count=1
```

以上均通过。Linux GUI 全量测试另有 `TestLANSharePanelRecommendsTheReachableAdapter` 失败：WSL 可选地址包含容器网桥，测试依赖的“存在可推荐网卡”条件不成立。干净 P0 提交 `166ac41` 在同环境复跑也失败，因此没有把 Linux GUI 全量测试写成通过。WSL 同时缺少 libpango，未据此声称完成原生 GUI 视觉验证。

测试不调用真实 VPN 登录、不更改系统代理、防火墙或系统软件。跨机组播、UAC、真实网关重连及流量负载仍需实际环境覆盖。

## 资源复测

诊断场景使用真实控制器与本地分享监听、替代 VPN/组播后端；命令与 P0 相同，`TestOptionalResourceBaseline -count=3`。原始输出在 `build/p1-resources-windows.log`。

| 轮次 | 页面预热后 GC HeapAlloc（字节） | 十轮启停后 GC HeapAlloc（字节） |
|---|---:|---:|
| 1 | 6,966,192 | 7,021,480 |
| 2 | 7,029,192 | 7,039,352 |
| 3 | 7,017,656 | 7,043,984 |

三轮均未触发 P0 的额外保留堆 2 MiB 调查门槛。30 次“关闭分享到公告已撤销”的记录为 4.38–59.58 毫秒；完整任务退出另由一秒预算回归测试验证。goroutine 总数还包含测试、GUI 与异步通知，功能任务断言按实际工作栈和退出信号检查。

原分享基线 `8a9a05e` 与 P1 开发产物交替启动，各三轮。两者使用同一 Go、Worker、编译选项和独立空配置；预热五秒、隐藏窗口、采样二十秒，未达到原有三十秒工作集修剪阈值。样本、配置、二进制哈希与摘要在 `build/p1/measurements/`。

| 版本/轮次 | Private Bytes 中位数 MiB | Working Set 中位数 MiB | 最高句柄数 |
|---|---:|---:|---:|
| 原分享 1 | 171.82 | 116.34 | 1499 |
| P1 1 | 166.42 | 157.21 | 1501 |
| 原分享 2 | 168.63 | 113.30 | 1480 |
| P1 2 | 170.30 | 114.07 | 1482 |
| 原分享 3 | 170.46 | 113.38 | 1482 |
| P1 3 | 164.72 | 110.23 | 1486 |

每轮 29–30 个样本，整棵进程树只有 Hub。中位数再取中位数分别为 170.46 与 166.42 MiB；P1 轮间跨度 5.58 MiB，首次 Working Set 也有明显波动。该小样本不能证明稳定节省 4.04 MiB，能够确认的是常驻可选任务已消除，未出现本次门禁定义的内存回归。活跃 VPN/Worker、多机流量与最小化恢复不由这组空闲数据代表。

## 回退与后续

P1 作为独立生命周期提交回退，持久化配置和 LAN 分享协议未变化。原始测量资料处于忽略的 build 目录，方法和摘要随代码提交。
P2 接着提取客户端契约与装配边界；P3 接入清理分支并完成任务进程化。P0–P3 整体目标尚未完成。
