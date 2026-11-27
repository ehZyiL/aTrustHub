# P5 Relay 进程隔离记录

日期：2026-11-27。产品分支：`refactor/component-boundaries`。

## 结果

`cmd/app-relay` 生成 `core/connect-hub-relay(.exe)`，处理 LAN 分享监听、导入连接会话和 DNS-SD 发布/浏览。Hub 保留 VPN 会话、资源归属、防火墙控制、配置存储和界面；每个分享/导入任务单独启动 relay 进程，发布与浏览共享一个惰性启动的 discovery 进程。任务结束后关闭控制通道，等待子进程退出。发现进程在发布和浏览都空闲后自行退出，后续操作可以重新启动。

relay 与 Hub 使用 stdin/stdout 上的版本化 JSON 控制消息。本机 loopback HTTP 通道使用每进程随机令牌传递受限快照、DNS 与严格拨号请求；TCP 隧道使用独立 hijack 流，不经过 JSON。导入流在资源版本变化、会话关闭或子进程退出时撤销。拨号只通过已有授权会话，不为未知目标或 relay 故障回退直连。防火墙仍由 Hub 和现有特权助手管理。

## 自动验证

- `go test -mod=readonly ./... -count=1` 通过，包含真实本机 mDNS 发布、浏览和加入端到端用例。
- relay 集成测试覆盖 host/import 字节流、DNS 成功与拒绝、未授权目标、过期资源版本、资源更新时断开旧流、正常停止和进程回收。
- discovery 进程测试覆盖惰性启动、空闲自动退出、再次启动和显式关闭。
- Hub 与 `cmd/app-relay` 分别通过 Windows/amd64、Linux/amd64、macOS/amd64 交叉构建。
- `git diff --check` 通过。

## Windows 进程树资源对照

2026-11-27 在 Windows/amd64、Go 1.27.4 上，用相同 buildtool 参数分别构建 P4 提交 `47ee037` 和 P5 提交 `16d3b1d`，两者固定相同的内核子模块提交 `5929e30`。使用 `scripts/measure-idle.ps1` 的独立空配置、5 秒预热、隐藏窗口、20 秒采样，交替各运行三轮。所有六轮进程树都只有 Hub：

| 版本/轮次 | Private Bytes 中位数 MiB | Working Set 中位数 MiB | 句柄中位数 |
|---|---:|---:|---:|
| P4 / 1 | 168.50 | 161.61 | 1477 |
| P5 / 1 | 169.51 | 159.51 | 1477 |
| P4 / 2 | 169.90 | 113.72 | 1482 |
| P5 / 2 | 169.62 | 113.21 | 1482 |
| P4 / 3 | 169.57 | 113.54 | 1488 |
| P5 / 3 | 166.23 | 110.42 | 1492 |

三轮中位数再取中位数后，P4/P5 Private Bytes 为 169.57/169.51 MiB，Working Set 为 113.72/113.21 MiB，句柄为 1482/1482。小样本下空闲占用基本持平；P5 的明确结果是无发现、分享或导入任务时没有 relay 进程，而不是声称 Hub 本体内存下降。

另用新增的 opt-in `TestRelayResourceProfile` 做本机合成回显负载对照，四条并发 TCP 流、20 秒运行，不连接 VPN。三轮采样的进程树 Private Bytes 中位数为进程内 relay 64.25 MiB、sidecar 115.41 MiB；sidecar 约多 51.16 MiB，来自并存的第二个 Go 运行时和 relay 任务。吞吐三轮中位数为 461.588/115.684 MiB/s，P95 往返延迟中位数约 0.562/1.068 ms（进程内/sidecar）。这是本机内存回显的合成压力场景，不代表真实 VPN 的吞吐；它明确显示启用 relay 时进程隔离有固定内存成本及额外本机转发开销。对从不使用可选功能的用户，sidecar 按需启动避免了该运行时常驻。

## 尚未实测

当前 Windows 环境没有 C 编译器，`go test -race` 因 `-race requires cgo` 无法运行。此次没有启动真实 VPN 登录、修改防火墙或执行清理/重启；跨机发现、Windows 入站 5353、macOS multicast 权限，以及真实 VPN 负载下的完整进程树资源/吞吐/延迟仍需在对应设备上验证。交叉编译和同机 mDNS 测试不替代这些验收。

## 联调

默认从 Hub 可执行文件旁的 `core/connect-hub-relay(.exe)` 查找组件。可以设置 `EASYCONNECT_RELAY` 指向指定组件；Hub 会在版本握手或任务通道失败时报告错误，不会静默回退到 Hub 内的 relay 实现。

合成负载复测时先设置 `EASYCONNECT_RELAY` 指向组件路径，再将 `CONNECT_HUB_RELAY_PROFILE` 设为 `inproc` 或 `sidecar`，运行 `go test -mod=readonly ./internal/relay/process -run '^TestRelayResourceProfile$' -count=1 -v`。该测试默认跳过，不会访问 VPN 或修改系统网络设置。
