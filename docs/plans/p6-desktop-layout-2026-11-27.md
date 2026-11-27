# P6 桌面应用与根目录整理

日期：2026-11-27。起点：`refactor/component-boundaries` / `ebee047`。
状态：代码与自动化验收已完成；原生窗口交互/正常退出尚未由助手验证（见执行记录），发行组合暂缓。

## 目标与范围

按本轮讨论调整 P6：优先解决产品根目录 152 个 Go 文件混放的问题。
标准版/扩展版及其构建标签暂缓，不作为本轮验收条件，也不借本轮调整功能或协议。
本轮不更改内核子模块、配置格式、凭据存储、进程协议、提权语义或网络授权规则。
目录整理不构成降低内存的证据。

```text
aTrustHub/
├── cmd/connect-hub/main.go       # 薄入口，只调用 desktop.Run
├── cmd/app-{helper,cleanup,relay}/
├── internal/
│   ├── desktop/                 # 窗口、页面、UI 状态与领域服务装配；同包测试随迁
│   ├── cleanup/client/          # 清理任务客户端及异步任务控制，不依赖 MyGo
│   ├── localapps/takeover/      # 资源接管控制器，不依赖桌面 app
│   └── ...                      # 保留既有领域包，不重排全部 internal
├── resources/                   # 保留图标真源；提供嵌入资源包，避免复制图标
├── docs/                        # 开发说明、平台入门、设计与验收记录
├── scripts/ packaging/ tests/ testdata/ third_party/
├── README.md LICENSE go.mod go.sum Makefile mygo.json
└── .github/ .gitignore .gitattributes .gitmodules
```

根目录不再保留业务或测试 `.go` 文件。原有未跟踪 `go.work`、`go.work.sum` 和
忽略的构建产物保持原样，不纳入提交。`internal/desktop` 首次迁移保持同包，
避免将依赖 app 私有字段的页面硬拆成相互依赖的小包；随后提取明确的非 UI 控制器，
其余页面继续按文件职责组织，后续拆包须有独立收益。

## 实施顺序与提交边界

### P6.1：迁移入口、桌面包和构建引用

- [x] 原根包源码和测试迁入 `internal/desktop`，只更改包名、入口及必要路径。
- [x] 新增 `cmd/connect-hub`，保留 watchdog、capture launcher、browser supervisor
  在普通 UI 启动之前的分发顺序。
- [x] MyGo `main` 明确指向新入口；统一 builder、Makefile 和 Windows `.syso`
  生成位置同步更新，打包产物名称和 `core/` 组件布局保持一致。
- [x] 图标从现有 `resources/icon.png` 嵌入，测试的模块根查找显式处理，不在生产代码
  中硬编码源码仓库路径，不通过全局 `chdir` 隐藏测试路径错误。
- [x] 完成全量回归和跨平台构建后单独提交，便于审核 rename 与回退。

### P6.2：提取控制器，缩小桌面包职责

- [x] 清理任务后台运行、取消、代次校验和单槽快照移到 `internal/cleanup/client`，
  页面保留选择、确认及展示，不把 UI 线程所有权改成任意后台写入。
- [x] 资源 TUN 控制器移到 `internal/localapps/takeover`；通过已有回调注入配置、
  runtime、系统代理恢复和通知，保留部分网关降级、失败清理重试等语义。
- [x] 原控制器测试随实现迁移；桌面保留页面与装配集成测试，不暴露生产内部状态
  只为方便测试，不引入通用插件/事件总线。
- [x] 添加依赖边界验证，确保控制器没有间接引用 MyGo 或 desktop。

### P6.3：文档、结构门禁与发行验证

- [x] 根目录四份开发/平台说明移入 docs，更新索引、有效源码链接和打包复制位置。
- [x] 增加结构测试：根目录无 Go 文件、入口与 MyGo 配置一致，核心包不反向依赖 desktop。
- [x] 运行全量测试、相关 vet、IPC 生成校验，Windows/Linux/macOS Hub 交叉构建。
- [x] 通过统一入口构建 Windows 配套组件和便携包，验证清单、图标、文档和版本来源。
- [x] 用独立临时空配置启动迁移后 Hub，确认日志与进程窗口已就绪；没有真实 VPN、代理设置或清理操作。
- [ ] 原生窗口交互与正常退出实机验收：Computer Use 管道不可用，不能作为已验证项。
- [ ] 完成最终记录和文档提交后推送（最终检查时更新）。

## 验收与回退

1. `git ls-files '*.go'` 中根目录文件为零；桌面包可导入，唯一产品 GUI 入口在 cmd。
2. `GOWORK=off go test -mod=readonly ./... -count=1` 通过，包括已有页面、真实本机
   mDNS 加入、组件生命周期和 Worker 黑盒测试；不把 skipped 测试记作成功覆盖。
3. 控制器可不链接 MyGo 独立测试；配置、内网离线保护、取消和恢复语义保持兼容。
4. 开发构建、MyGo 构建和发行脚本使用相同入口，Windows 图标资源在链接后清除。
5. 文档内可维护的相对链接有效；历史审查记录的旧路径不改写为伪造的新证据。
6. 记录 Windows 启动/退出烟测；跨系统构建不等于 Linux/macOS 实机 UI 验收，真实
   VPN、跨机发现及提权流程沿用前阶段未覆盖项，不因本轮迁移宣称通过。

回退按控制器提取、文档迁移、桌面目录迁移各提交反向执行；入口、资源和构建配置
必须一起回退。没有用户数据迁移，不清理用户配置、备份和现有组件恢复日志。

## 执行记录

- 迁移前：Windows/amd64、Go 1.27.4，`GOWORK=off go test -mod=readonly ./... -count=1`
  通过；日志保存在忽略的 `build/p6-baseline-tests.log`。
- 已核对的既有模式：`cmd/app-relay` 薄入口、`internal/cleanup/client` 的可替代 Runner
  与快照、`resourceTUNController` 的回调注入，以及 `scripts/buildtool` 的固定输入门禁。

## 实际结果与限制

- 根目录 152 个 Go 文件已迁走，GUI 薄入口为 `cmd/connect-hub/main.go`，业务和同包测试
  在 `internal/desktop`。控制器分别在 `internal/cleanup/client/controller.go` 和
  `internal/localapps/takeover/controller.go`；源码导航见 `internal/desktop/README.md`。
- 根目录四份开发/平台说明归入 docs，README 和打包复制路径同步；历史审查报告保留
  当时的路径/行号，未伪造为新位置的历史证据。原有 `go.work` / `go.work.sum` 未修改。
- 新增结构门禁核对根目录没有 Go 文件、MyGo 配置可被 Go 解析为桌面入口、控制器不依赖 MyGo；
  Windows/Linux CI 的既有契约测试加入桌面及两个控制器包。
- Windows/amd64、Go 1.27.4：全量 `go test -mod=readonly ./... -count=1`、
  `go vet -mod=readonly ./...`、`git diff --check` 通过。最后补充的关闭状态回归也通过。
- 两个独立控制器测试通过；资源接管包覆盖率 94.1%。清理 client 整包覆盖率 68.2%，
  不能把控制器局部高覆盖率当成整个 client 的覆盖率。未运行 race：沿用 P5 的 Windows
  无 C 编译器限制，不将普通并发用例当作 race 检测。
- Hub、relay、桌面测试二进制通过 Linux/amd64、macOS/amd64 交叉编译；Windows 本机构建与测试通过。
  这不证明 Linux/macOS 原生窗口行为、真实 VPN 或提权流程已通过实机验证。
- `./scripts/build.ps1 -development -out build/p6-development` 和 Git Bash 下
  `EASYCONNECT_DEVELOPMENT_BUILD=1 bash scripts/package-windows.sh` 均构建成功，
  包含 Hub、Worker、capture、cleanup 和 relay。默认 PATH 的 `bash.exe` 是 WSL，
  无法找到 Windows Go；Windows 打包实测显式使用 `C:/Program Files/Git/bin/bash.exe`。
- 便携包日志在 `build/p6-package-windows.log`，包目录 `build/connect-hub-windows-amd64-p6-audit`。
  SHA256、迁移后入门文档的逐文件哈希和 `.syso` 生成后清除均已核对。
- MyGo 的 `main` 必须是 `./cmd/connect-hub`，不带 `./` 会被当作 GOROOT 包。
  修复后 `go tool mygo build -skip-dmg -debug -platform windows/amd64 -o build/p6-mygo`
  成功生成 EXE 和 Setup；日志在 `build/p6-mygo-build.log`。该 MyGo 调试入口沿用原版本配置，
  不替代统一 builder 的配套组件发行流程。
- 从便携包用 `build/p6-smoke-profile` 独立空配置启动，实读进程主窗口和“窗口就绪”日志；
  没有导入真实接入点，没有运行清理任务。Computer Use 首次、重试及内核重置后均返回
  `native pipe unavailable / os error 2`，没有执行助手页面点击。
  之后实读到 `OnClose` 日志，测试进程已不存在；未观察退出动作或 exit code，故不声称正常退出验收通过。
  记录在 `build/p6-smoke-result.json`。源码关闭/取消/恢复路径由自动化用例覆盖。

## 提交边界

- `b26fef3`：补充调整后的方案。
- `b901b1a`：桌面包、薄入口、资源与构建引用的机械迁移。
- `d8a6840`：提取控制器及回归测试。
- `c34e0ad`：实测修正 MyGo 相对包路径、保留未使用清理功能的关闭状态并扩展 CI 门禁。
- 文档迁移和本验收记录单独提交；最终提交及远端同步状态以 `git log` / `git status` 为准。
