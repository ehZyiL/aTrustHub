# aTrust / EasyConnect 残留清理（设计提案 · 未实现）

> **状态**：提案。本文描述的是**将要实现**的行为，不是已核实的现状。
> 代码落地后，需把"设计"改为"核实版"并逐条对到源码；本文末尾的"待实机确认"清单是
> 唯一允许长期保持"未确认"的部分。
>
> 参考实现：[Clear_aTrust `stop_sangfor.py`](https://github.com/FlyingFishBall/Clear_aTrust)（MIT，v1.4）。
> 本文只搬它的**判据与清理顺序**，交互模型完全重写（原脚本靠 `input()` 节流，GUI 没有 stdin）。

## 1. 范围

| 项 | 在范围内 | 说明 |
|---|---|---|
| 官方 aTrust / EasyConnect / Ingress 客户端 | ✅ 检测 + 独立引导官方卸载 | **不进批处理流水线**，作为前置引导由用户在官方卸载器中完成 |
| 卸载后残留：服务、驱动、进程、注册表、文件 | ✅ | |
| 清理前全量备份与一键还原 | ✅ | 注册表、文件、证书、策略在删除前全量镜像备份，支持 CLI/GUI 一键还原 |
| Winsock NSP/LSP 目录条目（`SangforNsp` / `SangforLSP`） | ✅ | 卸载不干净时“网络坏了”的典型根因；**严禁直删注册表**，调 Win32 API / netsh 重置 |
| BHO / COM 注册项（`SangforBHO` 等） | ✅ | 浏览器里的残留插件与 CLSID 孤儿 |
| Sangfor 自签根证书（`LocalMachine\Root`） | ✅ | 实测会写入；按指纹（Thumbprint）精准匹配删除，删前导出备份 |
| 自升级产物（`SSL\Backup`、`1_*` DLL、`*_<时间戳>`） | ✅ | 实测每次登录可能增长，Clear_aTrust 未覆盖 |
| 残留虚拟网卡设备节点（`SangforVnic`） | ✅ 深度项，默认不选 | 设备管理器里删不掉的那张网卡 |
| 工作空间虚拟盘（`DOS Devices`） | ✅ | 只清目标含 Sangfor 特征的盘符条目，不动目录内容 |
| 浏览器组策略（Chrome / Edge / Chromium） | ✅ 深度项，默认不选 | 只删值内容含 Sangfor 特征的项，删前先备份导出 |
| DriverStore 驱动包（`pnputil`） | ✅ 深度项，默认不选 | 需重启 |
| `WinDivert` 驱动 | ✅ 深度项，默认不选 | **可能被其他抓包/VPN 工具共用** |
| aTrust 工作空间里的用户文档 | ❌ | 任何情况下都不删 |
| 系统网络设置（DNS / 路由 / 系统代理） | ❌ | 清理器不写网络配置（Winsock 异常兜底重置除外） |
| Connect Hub 自身文件、配置、计划任务 | ❌ | 排除名单硬编码 |

前提假设（已核实）：**Connect Hub 不依赖官方客户端**。`aTrustHub` 全量源码（排除 `third_party/`）
搜索 `Sangfor` / `Ingress` / `aTrustXtun` / `SdpVnic` 零命中，网络层走自己的 Wintun + 协议栈，
因此卸载官方客户端不会削弱本软件能力。

## 2. 进程模型：独立 exe，不进 GUI 进程

GUI 全程普通用户权限（见 [architecture.md](architecture.md) §1），而清理必须管理员权限。
两个选择被否掉：

| 方案 | 否掉的原因 |
|---|---|
| 塞进 `connect-hub-capture.exe` | 那是网络助手协议 v7 的载体，加命令会破坏协议契约与打包校验（`package-windows.sh` 有协议号断言） |
| GUI 进程内 `runas` 提权自身 | 破坏"GUI 永不提权"的架构约束，且提权后无法回到普通权限 |

采用 **`connect-hub-cleanup.exe`**：console 子系统，一次性任务，独立的参数契约与报告文件。

```
普通权限                                   管理员权限
──────────────────────────────────────────────────────────────
connect-hub.exe（GUI）
  ├─ scan  : newCmd(exe, --scan --json ...)  → 不提权，同步拿退出码（快速只读探测）
  ├─ apply : ShellExecuteEx("runas", exe, --apply <plan.json> --report <path> ...)
  │                                           → 拿 hProcess，捕获退出码
  │                                           → 提权进程内部执行前自动复核特权残留
  │                                           → 先执行全量快照备份（manifest + 文件/注册表）
  │                                           → 逐条清理并写 report.jsonl，GUI 轮询进度
  └─ restore: ShellExecuteEx("runas", exe, --restore <manifest.json> --report <path> ...)
                                              → 一键回滚还原
```

**提权与进程控制机制**：
- GUI 提权时不绕道 `powershell.exe`（避免执行策略限制、冷启动慢与安全软件告警），直接在 Go 侧调用 `windows.ShellExecuteEx` 传 `Verb: "runas"` 并带 `SEE_MASK_NOCLOSEPROCESS` 标志获取进程句柄 `hProcess`。
- GUI 同时监控 `hProcess` 状态与 `report.jsonl` 文件流：以 `report.jsonl` 的 `end` 事件更新进度条，以 `hProcess` 的进程退出码作为物理终止判定，彻底杜绝崩溃死挂。

## 3. 命令行契约

```
connect-hub-cleanup.exe [flags]

  --scan                  只读扫描，产出 plan
  --out <path>            plan 输出路径（缺省写 stdout）
  --apply <plan.json>     执行 plan（包含前置备份）
  --restore <manifest>    从备份清单还原
  --list-backups          列出历史备份点
  --backup-dir <dir>      指定备份存储根目录（缺省为 AppData/cleanup/backups）
  --report <path>         执行进度 JSONL（--apply / --restore 时必需）
  --json                  stdout 输出机器可读 JSON（GUI 用）
  --no-elevate            禁止自提权（GUI 扫描阶段；apply/restore 时若未提权会以退出码 4 拒绝）
  --hide                  自提权时隐藏控制台窗口（GUI 批处理执行阶段）
  --only <id,id>          只执行指定条目
  --skip <id,id>          跳过指定条目
  --yes                   跳过交互确认（GUI 执行阶段；plan 中的深度项必须已被显式勾选）
  --protocol-version      打印清理器协议版本（当前 2），供打包脚本自检
```

无参数启动 = 交互模式（自提权 → 扫描 → 清单 → 确认 → 自动备份 → 执行 → 按 Enter 退出）。

退出码：

| 码 | 含义 |
|---|---|
| 0 | 全部成功，或无需处理（无残留） |
| 1 | 有项失败（详情在 report / stdout） |
| 2 | 用法或参数错误 / 备份创建失败阻断 |
| 3 | 全部成功，但有需重启才彻底生效的项（如驱动卸载、DELAY_UNTIL_REBOOT） |
| 4 | 权限不足：UAC 被取消，或 `--no-elevate` 下要求 apply / restore |

## 4. 数据契约

### 4.1 `plan.json`（扫描产物 = 待办清单）

```json
{
  "version": 2,
  "scannedAt": "2026-11-22T18:32:11+08:00",
  "elevated": false,
  "requiresElevationForCompleteScan": true,
  "installed": [
    {
      "name": "aTrust 5.3.8",
      "uninstall": "\"C:\\Program Files (x86)\\Sangfor\\aTrust\\uninst.exe\"",
      "hive": "HKLM",
      "key": "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\aTrust"
    }
  ],
  "findings": [
    {
      "id": "svc:eaio_service",
      "group": "service",
      "family": "atrust",
      "title": "eaio_service",
      "detail": "服务 · 运行中",
      "risk": "normal",
      "action": "delete-service",
      "params": { "name": "eaio_service" },
      "selected": true
    },
    {
      "id": "drv:WinDivert",
      "group": "driver",
      "title": "WinDivert",
      "detail": "驱动 · 可能被其他抓包工具共用",
      "risk": "deep",
      "action": "delete-service",
      "params": { "name": "WinDivert", "isDriver": true },
      "selected": false
    }
  ],
  "warnings": ["普通权限扫描可能遗漏部分受系统保护的特权驱动与服务，清理执行阶段将自动进行提权复核"]
}
```

约束：

- `id` 全局唯一且稳定（`<group>:<natural-key>`），GUI 的勾选状态、`--only/--skip`、report 都靠它关联。
- `risk` 只有 `normal` / `deep` 两档，`deep` 一律 `selected: false`。
- `installed` **仅作为独立引导项展示在 GUI/交互模式前端**，不再混入清理 `action`，彻底避免批处理中拉起官方卸载器的时序冲突。
- `action` 封闭枚举与语义修正：

| `action` | `params` | 语义 |
|---|---|---|
| `delete-service` | `name`, `isDriver` | `sc stop` → `sc delete`；驱动无法停止或处于 `DELETE_PENDING` 时标记为 `reboot` |
| `kill-process` | `image` | `taskkill /f /im`，排除自身与 `core/` 下程序 |
| `delete-registry` | `hive`, `key`, `subkeys` | 先导出到备份目录，再递归删除 |
| `delete-path` | `path` | 备份原文件后移动到隔离区；被占用则递归遍历子项注册 `MoveFileEx(DELAY_UNTIL_REBOOT)` |
| `clear-dos-device` | `name`, `letter` | `subst <letter> /D` + 删 `DOS Devices` 值（仅限目标含 Sangfor 关键字的项） |
| `delete-policy-value` | `hive`, `view`, `key`, `value` | 先导出备份，再删单个值，随后回收空子键 |
| `delete-driver-package` | `inf` | `pnputil /delete-driver <inf> /uninstall /force` |
| `uninstall-winsock-provider` | `catalog`, `providerId`, `isNameSpace` | **禁止直删注册表**；调 `WSCUnInstallNameSpace` 或 `WSCDeinstallProvider`，失败兜底 `netsh winsock reset` |
| `remove-device` | `instanceId` | `pnputil /remove-device <id>`，清残留的虚拟网卡设备节点 |
| `delete-cert` | `store`, `thumbprint`, `subject` | 按 SHA1 指纹导出证书备份（`.cer`），再精准从 `Root` 存储删除 |

### 4.2 `report.jsonl`（执行进度，逐行 append + flush）

```json
{"ts":"...","event":"start","total":6,"elevated":true,"backupId":"20261123-163000"}
{"ts":"...","event":"backup","status":"ok","message":"已完成清理前全量快照备份"}
{"ts":"...","event":"item","id":"svc:eaio_service","status":"ok","message":"服务已删除"}
{"ts":"...","event":"item","id":"drv:SfRemoveCallback","status":"reboot","message":"被占用，已标记重启后删除"}
{"ts":"...","event":"item","id":"reg:HKLM\\SOFTWARE\\Sangfor","status":"failed","message":"拒绝访问"}
{"ts":"...","event":"end","ok":5,"failed":1,"reboot":2,"exit":3,"backupManifest":"C:\\Users\\...\\manifest.json"}
```

`status` 枚举：`ok` / `reboot` / `failed` / `skipped` / `canceled`。

### 4.3 `backup-manifest.json`（备份清单与还原元数据）

每次执行 `--apply` 清理前，必须在 `<backup-dir>/<backupId>/` 下生成该清单，记录所有被清理资产的原始位置与备份副本映射：

```json
{
  "version": 1,
  "backupId": "20261123-163000",
  "createdAt": "2026-11-23T16:30:00+08:00",
  "planSnapshot": "plan.json",
  "registry": [
    {
      "hive": "HKLM",
      "key": "SOFTWARE\\WOW6432Node\\Sangfor",
      "view": "32",
      "backupFile": "registry/HKLM_WOW6432Node_Sangfor.reg"
    }
  ],
  "files": [
    {
      "originalPath": "C:\\Program Files (x86)\\Sangfor\\SSL\\ClientComponent\\SangforNsp.dll",
      "backupPath": "files/Program Files (x86)/Sangfor/SSL/ClientComponent/SangforNsp.dll",
      "size": 182320,
      "sha256": "..."
    }
  ],
  "certificates": [
    {
      "store": "Root",
      "thumbprint": "ABCDEF123456...",
      "subject": "CN=Sangfor CA...",
      "backupFile": "certs/SangforCA.cer"
    }
  ],
  "policies": [
    {
      "hive": "HKLM",
      "key": "SOFTWARE\\Policies\\Google\\Chrome\\ExtensionInstallAllowlist",
      "value": "1",
      "data": "..."
    }
  ],
  "winsock": {
    "snapshotBeforeReset": "winsock/catalog_backup.reg"
  }
}
```

还原命令：`connect-hub-cleanup.exe --restore <backup-dir>/<backupId>/manifest.json`。

## 5. 扫描判据

### 5.1 两族组件几乎不重叠（本轮最重要的结论）

Clear_aTrust 的名单针对 aTrust / Ingress 系；EasyConnect 7.x 是另一套完全不同的组件。
按单一名单扫描会**双向漏检**：

| | EasyConnect 7.x（SSL VPN） | aTrust / Ingress（零信任） |
|---|---|---|
| 服务 | `SangforServiceClient`、`SangforPromoteService`、`SangforUpdate`、`SJobber` | `eaio_service`、`nac_monitor`、`IngressMgr`、`SangforSP`、`SangforPWEx` |
| 驱动 | `SangforVnic`、`SangforTcpDrv`、`SangforDnsDrv` | `SdpVnic`、`aTrustXtun`、`SfRemoveCallback`、`WinDivert` |
| 注入层 | `SangforNsp`（Winsock NSP）、`SangforLSP`、`SangforBHO`（IE BHO）、若干 COM | 浏览器策略、防火墙规则 |

判据表按族分两套，`plan.json` 的 finding 增加 `family: "ec" | "atrust"`，用于界面分组与文案。

### 5.2 关键字与分类匹配收敛（防误伤）

为防止将 Kubernetes/本地反向代理的 `ingress` 或普通无害进程误判，关键字做精确化限制：

```
sangfor | 深信服 | atrust | eas(y)?connect | eaio | nac_monitor | nac_agent
sdpvnic | atrustxtun | sfremovecallback | sangforhelpertool
sangforvnic | sangfortcpdrv | sangfordnsdrv | sangfornsp | sangforlsp | sangforbho
sangforserviceclient | sangforpromoteservice | sangforupdate | sjobber | sangforcore
sangforcdc | sangforl3vpn | sangforsddn | sangforwebuictrl | sangforrapp
ingressmgr | ingress manager | ingress_service
```

> **注**：`ingress` 词缀必须匹配完整组件名（如 `IngressMgr`、`Ingress Manager`），不得单独以子串 `ingress` 粗暴通配全局。`WinDivert` 仅限 `risk: deep`。

| 分组 | 判据 | 数据源 | 风险 |
|---|---|---|---|
| `installed` | 注册表键名 **或** `Publisher` **或** `UninstallString` 命中（DisplayName 会被租户改名，不能单独用） | HKLM/HKCU `...\CurrentVersion\Uninstall` + `WOW6432Node` | 仅做独立前置引导 |
| `service` | SCM 子键名**或** ImagePath 命中关键字（名字可能带 `_7,5,0,1` 后缀） | `HKLM\SYSTEM\CurrentControlSet\Services` | normal |
| `driver` | SCM 驱动 ImagePath 的文件 ∪ `System32\drivers\*` ∪ `Program Files*\Sangfor\**\*.sys` | 三处都要扫 | `WinDivert` 单独降为 deep |
| `process` | 进程名**或**可执行路径命中关键字（两者不一致，见 `SangforSP`） | 进程快照 / CIM | normal |
| `registry` | 固定键表 ∪ `Services`/`Classes\CLSID` 命中（**64/32 两个视图都扫**） | `winreg` 显式 `WOW64_64KEY`/`WOW64_32KEY` | normal |
| `winsock` | `LibraryPath` / `ProtocolName` 解码结果**含 sangfor** | Win32 Winsock Enum API + 注册表反查（必须记录 Provider GUID/Catalog ID） | normal（调系统 API 卸载，绝不直删键值） |
| `bho` | 已知 ProgID 列表 ∪ `Browser Helper Objects\{CLSID}` 反查 `InprocServer32` | `Classes\<ProgID>` → `CLSID` → `InprocServer32` | normal |
| `netadapter` | `DriverDesc` 或 INF 的 `DisplayName` 命中关键字 | 网卡类注册表 + `pnputil /enum-devices /class Net` | deep |
| `cert` | 证书 `Issuer` / `Subject` 命中 Sangfor 特征，提取 SHA1 `Thumbprint` | `Cert:\LocalMachine\Root` | normal（按指纹精准删除，删前导出备份） |
| `firewall` | 规则的 `Program` 路径命中关键字 | Windows Firewall COM / NetSecurity API | normal |
| `file` | 已知根深度 ≤3；**必含** `SSL\Backup`、`1_*`、`*_<时间戳>`、`%TEMP%\1_*`、`SangforPAC` | 目录遍历 | normal |
| `virtualdrive` | `DOS Devices` 里盘符格式条目，**且目标必须含 Sangfor 关键字** | `HKLM\SYSTEM\...\Session Manager\DOS Devices` | normal |
| `browserpolicy` | 值数据（含 REG_MULTI_SZ 拼接后）命中关键字 | HKLM/HKCU × 64/32 视图 × Chrome/Edge/Chromium | deep |
| `driverpackage` | `DriverStore\FileRepository` 目录名命中（形如 `sangforvnic.inf_amd64_<hash>`） | `pnputil /enum-drivers` 交叉验证 | deep |

### 5.3 `virtualdrive` 判据修正

- 只处理 `^[A-Za-z]:$` 的盘符条目；`AUX`/`CON`/`NUL`/`PRN`/`PIPE` 等系统设备名跳过；
- 目标以 `\DEVICE\` 开头 → `manual`；
- **目标必须明确包含 Sangfor 关键字**才判为 `suspicious`；
- **防误判安全约束**：若目标路径失效/不存在，但原目标路径**不含** Sangfor 关键字（例如用户自行建立的普通失效 `subst` 目录），判定为 `kept`，**绝对不清理**。

### 5.4 普通权限扫描与提权执行的复核闭环

- **GUI 初始扫描（普通权限）**：快速列出大部分用户态残留及已知系统服务/注册表键。若检测到受限项（如驱动状态不可探知、证书读取受阻），在 `plan.json` 中标记 `requiresElevationForCompleteScan: true`。
- **Apply 阶段提权复核（Rescan & Merge）**：提权拉起 `connect-hub-cleanup.exe --apply <plan.json>` 后，执行器会立即以管理员权限进行一次全量静默复核扫描，并将新发现的特权级残留（且符合 plan 中已有已选分类的项）自动合并纳入本次执行任务，避免由于普通权限漏扫导致的残留遗忘。

## 6. 执行顺序、备份与幂等机制

### 6.1 零数据损失（Zero Data Loss）备份机制

在执行任何删除或修改操作前，必须先完成统一快照备份：
1. **注册表备份**：对将要删除的注册表项，调用 Win32 `RegSaveKeyEx` 或 `reg export <key> <backupPath>` 生成可直接双击导入的 `.reg` 文件。
2. **文件备份**：
   * 将目标文件完整复制到 `<backup-dir>/<backupId>/files/`，若目标被占用，以只读共享模式（`FILE_SHARE_READ | FILE_SHARE_WRITE`）复制；
   * **跨卷移动处理**：如果备份目录与源文件不在同一驱动器盘符，严禁直接使用原子 Rename，必须采用 Copy+验证哈希，确认备份无损；
   * 超过 200MB 的冗余安装包（如 TEMP 下临时包）可经用户配置选择仅记录哈希不复制，避免撑爆磁盘。
3. **证书备份**：通过 CryptoAPI 将待删除证书完整导出为标准 X.509 DER/CER 文件。
4. **生成 `manifest.json`**：记录所有映射关系，写入 `backup-manifest.json`。
   > **强约束**：备份阶段任何致命错误（如磁盘满、注册表导出失败）直接中止流程，退出码 2，不进入删除阶段。

### 6.2 执行顺序（释放依赖链）

```
0. 全量快照备份          生成 manifest.json、导出注册表、归档文件、备份证书
1. kill-process         终止残留守护与自升级进程（解除文件句柄占用）
2. delete-service       停止并删除系统服务
3. delete-service(驱动) 停止驱动服务（无法停止或返回 PENDING 则标记 reboot）
4. remove-device        深度：残留的虚拟网卡设备节点（pnputil /remove-device）
5. uninstall-winsock    调用 WSCUnInstallNameSpace / WSCDeinstallProvider（失败调 netsh reset）
6. delete-registry      删除注册表残留树与 BHO/COM 孤儿项
7. delete-cert          按指纹精准删除 Sangfor 自签根证书
8. delete-policy-value  深度：删除浏览器恶意策略并回收空键
9. clear-dos-device     清理虚拟盘映射
10. delete-driver-package 深度：DriverStore 驱动包移除
11. delete-path         清理残留文件：
                        ├─ 未被占用：移动至隔离区并记录
                        └─ 被占用：递归遍历所有子文件逐个调用 MoveFileEx(DELAY_UNTIL_REBOOT)，
                           最后将父目录同样注册到 PendingFileRenameOperations
12. 收尾                清理空目录、同步写出 report.jsonl 的 end 事件
```

### 6.3 一键还原机制（Restore Phase）

当用户误删或网络环境需要恢复时，执行 `connect-hub-cleanup.exe --restore <manifest.json>`：
1. **注册表还原**：静默调用 `reg import <backupFile>`，恢复所有被删注册表树；
2. **文件还原**：将 `files/` 目录下的备份文件按原始路径复制回原位（若原路径被新版本占用则跳过）；
3. **证书还原**：调用 `certutil -addstore -f Root <certFile>` 重新导入根证书；
4. **Winsock 恢复**：若执行过重置，提示用户重启以使 Winsock Catalog 完全就绪；
5. **清理延迟删除注册**：检查并清理注册表 `PendingFileRenameOperations` 中涉及这些文件的待删除标记；
6. 产出 `restore-report.jsonl`，返回退出码 0。

## 7. 提权与进程控制

```go
// cmd/app-cleanup/elevate_windows.go
func runElevatedAndWait(exe string, args []string, hide bool) (uint32, error) {
    // 1. 使用 windows.ShellExecuteEx 传递 Verb: "runas"
    // 2. 设置 fMask = windows.SEE_MASK_NOCLOSEPROCESS 获取真实 hProcess 句柄
    // 3. 显式传 Directory: filepath.Dir(exe)，防止 CWD 沦为 System32
    // 4. 等待进程结束：windows.WaitForSingleObject(hProcess, windows.INFINITE)
    // 5. 获取实际退出码：windows.GetExitCodeProcess(hProcess, &exitCode)
    // 6. 关闭句柄 windows.CloseHandle(hProcess)
}
```

- **不依赖 PowerShell**：彻底规避 ExecutionPolicy、系统版本兼容性与冷启动开销。
- **双重保险**：GUI 通过 `hProcess` 监听生命周期；UI 进度通过每 200ms 消费 `report.jsonl` 实现平滑流式刷新。

## 8. GUI 接线

设置页新增第 5 段（`ui.Segmented` 增加「维护」）。段内分为清晰的四块：

| 块 | 内容 |
|---|---|
| **1. 官方卸载引导** | 若检测到官方客户端，显示 `[启动官方卸载器]` 按钮；完成并关闭官方卸载器后，自动刷新检测状态 |
| **2. 残留清理** | 分组勾选清单（建议项默认全选，深度项默认不勾并标注风险）+ `[重新扫描] [开始清理]` |
| **3. 执行进度与结果** | 进度条 + 实时事件流 + 结果汇总：`成功 N / 需重启 K / 失败 M` + `[打开报告] [重启电脑]` |
| **4. 备份管理与一键还原** | 显示最近备份点时间戳 + `[从备份还原] [打开备份目录]`，用户误操作可无损回滚 |

- **冲突互斥**：TUN 活跃时阻断清理，弹窗提醒先断开连接。
- **UAC 被拒处理**：若用户取消 UAC 弹窗，进程返回码 4，GUI 弹出非侵入性提示并停留在就绪页，不进入错误锁死状态。

## 9. 安全边界

明确不碰：
- aTrust 工作空间目录里的用户文档
- 无 Sangfor 特征值的浏览器策略与用户私有 `subst` 驱动器
- 非 Sangfor 相关的 Winsock Catalog 条目
- Connect Hub 自身进程、数据目录与计划任务
- 任何无法完成备份的操作（备份失败必须直接熔断退出）

## 10. 文件清单

```
aTrustHub/
├── internal/sangforclean/
│   ├── targets.go            关键字表、已知服务/驱动/进程、固定注册表键、策略标记
│   ├── classify.go           纯函数：卸载项匹配、DOS Devices 分类、策略值分类
│   ├── classify_test.go      单测
│   ├── plan.go               plan/report 结构 + JSONL 写入
│   ├── plan_test.go
│   ├── scan_windows.go       扫描逻辑与特权复核
│   ├── backup_windows.go     全量快照备份（RegExport/FileCopy/CertExport/Manifest）
│   ├── restore_windows.go    一键还原（RegImport/FileRestore/CertImport）
│   ├── winsock_windows.go    Win32 WSC API 封装与 netsh reset 兜底
│   ├── apply_windows.go      按 action 分派执行、隔离与延迟删除
│   ├── elevate_windows.go    原生 ShellExecuteExW 提权与进程句柄管理
│   └── *_other.go            非 Windows：ErrUnsupported
├── cmd/app-cleanup/
│   ├── main.go               参数解析（--scan, --apply, --restore 等）、交互模式
│   └── main_other.go         非 Windows stub
├── cleanupview.go            GUI：维护段 + 卸载引导 + 清单 + 进度 + 备份还原
├── cleanup_windows.go        定位 exe、ShellExecuteEx 调用、report 轮询
├── cleanup_other.go          非 Windows 空实现
└── docs/design/maintenance.md 本文件
```

打包：[scripts/package-windows.sh](../../scripts/package-windows.sh) 增加一行编译到**包根目录**（不是 `core/`，
`COMPONENTS.txt` 已声明 `core/` 是内部程序），并加 `--protocol-version` 自检；
[installer.nsi](../../packaging/windows/installer.nsi) 增加开始菜单快捷方式「清理 aTrust / EasyConnect 残留」。

## 11. 许可

Clear_aTrust 是 MIT，本仓是 AGPL-3.0。移植其判据表与分类逻辑需：

- 相关源文件头保留 `// 判据取自 Clear_aTrust（MIT License, Copyright (c) 2026 FlyingFishBall）`
- `LICENSES/Clear_aTrust-MIT.txt` 随包分发（`package-windows.sh` 的 `install -m 0644` 一行）

## 12. 待实机确认（唯一允许长期未确认的部分）

| # | 待确认 | 影响 | 状态 |
|---|---|---|---|
| 1 | aTrust 系与**其他版本**的服务名、驱动名、安装目录 | 关键字表需迭代 | EasyConnect 7.6.7 **已确认**（§5.3）；**租户定制包会把 DisplayName 改成租户品牌**；aTrust 系未确认 |
| 2 | 官方卸载器的静默参数与失败可见性 | `run-uninstaller` 的等待与判定 | 多级卸载器 + 要求重启**已确认**；静默参数未确认 |
| 3 | `SfRemoveCallback` 等驱动保护导致的删除失败率 | 是否必须依赖重启路径 | 未确认（EasyConnect 未装它） |
| 4 | `gpupdate /force` 后 Chrome/Edge 是否立即解除“由组织管理” | 深度项成功判据 | 未确认 |
| 5 | `DriverStore` 目录名与 INF 名匹配规则 | `delete-driver-package` 误伤风险 | **已确认**：`sangforvnic.inf_amd64_<hash>`，服务 DisplayName 指向 `oem41.inf` |
| 6 | 企业机上策略键里是否存在仅大小写不同的合法项 | 逐值删除边界 | 未确认 |
| 7 | `SangforNsp` 条目在哪个视图、几条 | `winsock` 组会漏扫 | **已确认**：HKLM 64 位 `NameSpace_Catalog5` 下 **2 条**（ID 1、7），登录后改指 `1_SangforNsp.dll` |
| 8 | `SangforLSP` 是否真写 `Protocol_Catalog9` | 决定是否值得扫 | **已确认**：装机后 6 条 `SangforLSP_def over [...]`，登录后消失（临时注册） |
| 9 | 虚拟网卡设备节点形态 | `netadapter` 匹配规则 | **已确认**：`DriverDesc = Sangfor SSL VPN CS Support System VNIC`，INF `oem41.inf` |
| 10 | 官方卸载器跑完后到底还剩什么 | **整个功能的核心指标** | **已确认**（§5.3）：服务 `SangforPWEx` + `SangforVnic` 驱动包 + 注册表树 + 根证书 + 4 条防火墙规则 + 卸载器自身 3 个文件 + `%TEMP%` 21 MB，共 42 项 / ≈44 MB |
| 11 | 自升级（`SangforPWEx`/`Backup`/`1_*`）是否所有网关都发生 | 残留量预估 | **已确认**（本机发生一次）；其他网关未知 |
| 12 | 卸载后是否自动清 LSP/NSP 条目 | 决定 `winsock` 组的优先级 | **已确认**：NSP 2 条被清（27→19），LSP 登录后已自行消失 → `winsock` 降为兜底 |

## 13. 实施里程碑

| 批次 | 交付物 | 验收方式 |
|---|---|---|
| **B1**（≈2d） | `internal/sangforclean` 纯逻辑 + 单测 + `--scan --json` | `go test ./internal/sangforclean`；真机跑扫描，只看清单质量，零改动 |
| **B2**（≈2.5d） | 全量备份 + `--apply` + `--restore` 还原 + 隔离 + report.jsonl + 交互模式 + 打包 | 真机清理 → 验证备份包完整度 → 执行 `--restore` 验证一键还原回到原样 → 重新清理 → 重启复查残留消失 |
| **B3**（≈2.5d） | GUI「维护」段（含卸载引导、残留勾选、进度流、一键还原入口）+ 互斥 + 文档转"核实版" | 界面流程、失败展示、UAC 拒绝分支、一键还原交互验收 |

B1 结束是唯一的决策闸门：清单质量不达标时，B2/B3 的估时要重做。
