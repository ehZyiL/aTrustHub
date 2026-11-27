# P6 当前版本构建与资源复测

日期：2026-11-27。产品源码：`a9a1f942b1be8f4a9331e891765ee7081c15beb0`。
对应 [根目录整改](p6-desktop-layout-2026-11-27.md)、
[桌面职责拆分](p6-desktop-followup-2026-11-27.md) 与
[LAN 职责整理](p6-lan-desktop-followup-2026-11-27.md)。

## 范围

在代码整理与全量回归完成后，复用已有测量工具建立当前版本的可重复基线。
本轮没有新增性能采集接口或产品功能，没有登录 VPN、修改系统代理、防火墙或清理环境。
原生窗口交互与正常退出仍待人工验收，本记录不替代该项。

## 最终配套构建

Windows/amd64、Go 1.27.4，固定内核 `5929e30`、`GOWORK=off`：

```powershell
./scripts/build.ps1 -development -out build/p6-final-development
```

构建包含 Hub、Worker、capture、cleanup、relay、图标、manifest 与模块清单，
全部成功；IPC 生成一致性检查通过，manifest 各 SHA256 逐项匹配，生成的 Windows
`.syso` 已删除。该目录是开发构建，不是安装包；日志在 `build/p6-final-build.log`。
manifest 记录被测产品提交与固定内核来源，不将后续纯文档提交混写为被测源码。

## Windows 空闲进程树

复用 [measure-idle.ps1](../../scripts/measure-idle.ps1)，每轮使用新的独立配置目录：
无接入点、凭据、分享、接管或更新；预热 5 秒，隐藏测试窗口后采样 20 秒，
名义采样间隔 500 毫秒。采集与终止仅作用于脚本创建的空配置实例。
这一固定测量状态不属于页面点击或正常退出实机验收。

三轮没有并行运行测试或编译。原始样本、配置、EXE 哈希及摘要在
`build/p6-final-idle/run-{1,2,3}` 和 `build/p6-final-idle/summary.json`。

| 轮次 | 样本数 | Private Bytes 中位数 MiB | Working Set 中位数 MiB | 最大句柄数 |
|---|---:|---:|---:|---:|
| 1 | 29 | 166.184 | 157.277 | 1489 |
| 2 | 30 | 167.523 | 111.508 | 1488 |
| 3 | 29 | 167.480 | 111.379 | 1494 |

三轮中位数再取中位数为 Private Bytes **167.480 MiB**、Working Set **111.508 MiB**。
所有 88 个样本都只有 Hub，未出现 relay、cleanup 或 Worker 子进程。
隐藏后 Get-Process 报告 `no-main-window`，不将其解释为窗口销毁。

第一轮 Working Set 明显偏高，保留原始样本且不推测原因。Private Bytes 的轮间跨度
为 1.339 MiB，Working Set 的跨度为 45.898 MiB；这些短期空闲数据不能证明长期无泄漏。
本轮没有重新交替测量 `dev-main` 或 P5，所以不把与历史表格的差值解释为稳定节省量，
也不据此宣称已通过与基础版配对比较的全部性能预算。

## 分享与发现的保留堆和停止

```powershell
$env:GOWORK = 'off'
$env:CONNECT_HUB_MEASURE_RESOURCES = '1'
go test -mod=readonly ./internal/desktop `
  -run '^(TestOptionalResourceBaseline|TestUnusedSharingHasNoBackgroundTasks|TestOptionalResourcesStopAndRestartTenTimes)$' `
  -count=3 -v
```

三个用例各执行三次，全部通过。诊断使用真实控制器、本机分享监听及替代 VPN/组播后端，
不是原生 GUI 或真实 VPN 负载；进程化 relay 的边界和合成负载结果仍见 [P5](p5-relay-process-2026-11-27.md)。

| 轮次 | 页面预热后 GC HeapAlloc 字节 | 十轮启停后 GC HeapAlloc 字节 | 增量字节 |
|---|---:|---:|---:|
| 1 | 7046704 | 7044288 | -2416 |
| 2 | 7070384 | 7063512 | -6872 |
| 3 | 7059600 | 7079136 | 19536 |

最大正增量 19536 字节，约 19.08 KiB，未触发 P0 保留堆额外 2 MiB 的调查门槛。
30 个“Disable 开始至公告已撤销”样本为 3.161–4.437 毫秒；完整功能任务在一秒内退出
另由生命周期用例断言，不将撤销公告耗时等同于全部资源释放时间。
未使用时没有新增功能专用常驻任务的断言重复三次通过；不以 goroutine 总数代替这一断言。
日志与摘要在 `build/p6-final-resources.log` 和 `build/p6-final-resource-summary.json`。

## 剩余验收

- 原生主界面、设置/清理页、分享/发现页与正常退出：自动控制通道此前恢复失败，人工结果待回复。
- 真实 VPN、跨机发现、提权与持续流量下的完整进程树：本轮未执行。
- 第一轮高 Working Set 的成因、长期保留与配对性能预算：未做归因，不据短样本宣告完成。
- 标准版/扩展版发行组合保持暂缓。

最终检查没有遗留本轮测试创建的 Hub、relay 或 cleanup 进程；原有工作区文件和用户配置未修改。
