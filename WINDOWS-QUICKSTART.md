# Windows 多网关系统 TUN 与软件接管测试版

当前阶段：多网关系统 TCP 接管已完成生产路径自动化验证，真实 UAC、Wintun、NRPT、重连和共存正在验收。用户于 2026-11-20 确认过旧版本 Windows DBX 软件接管成功；该反馈不代表此次新系统模式已通过实测。

构建标识：`0.1.0-dev-multigateway-tun.11`。请将整个压缩包解压后再运行，只拷贝单个 EXE 会缺少 `core\` 里的内部程序。Windows 网络助手协议为 7，EasyConnect worker 协议仍为 6。版本不匹配时在 UAC 前提示重新解压完整包。`COMPONENTS.txt` 记录配套协议及能力范围，`SHA256SUMS` 覆盖包内所有文件（清单自身除外）。网关卡片分别显示网关 DNS 与实际授权 TCP 探测状态；未配置有效 TCP 目标时显示未验证。

“网络授权与路由 → 用户策略”的同业务出口组可明确勾选“名称服务也等价”。新 DNS 查询按组内顺序选择在线的名称归属网关；固定 DNS 归属仍优先。它只在网关离线时切换，不在解析超时后跨网关查询，也不改绑已发布的地址；默认关闭。仓库 `scripts/` 目录内的 `measure-tun-performance.py` 用于后续受控 HTTP 服务的性能对照，需要 Python 3 和 curl，只随验收包（`EASYCONNECT_BUNDLE_PROFILE=test`）分发，使用 `--help` 查看参数。

**系统 TUN** 复用已登录 worker，以资源归属选择网关；旧 aTrust TUN 入口独立保留。系统模式启动完成后才暂停本应用自己的系统代理，停止或失败时恢复。第三方/自动代理原样保留，不阻止资源捕获；使用第三方代理的应用仍遵循它的分流规则。未完成的清理会阻止新启动，界面显示原因并提供重试清理。

`.5` 增加业务 IPv4 UDP 试验，仅供配套 EasyConnect L3 会话的已授权系统资源使用，真实网关应答待验。显式代理和按软件接管仍维持原范围。

`.6` 修复网关下发的 IPv6 地址、地址段和静态 DNS 记录漏判。系统 TUN 会提示这些内网资源不支持接管。

`.3` 修复网络助手异常退出后“重试清理”无法完成的问题：先确认原助手已退出、对应网卡消失、DNS 恢复记录清除，再释放旧接管会话；清理尚未完成时继续提示重试。旧版入口的周期日志已标明“旧版 TUN 巡检”，其 `on=false` 不代表新系统 TUN 关闭。

保留 `windows-capture.3` 的 IPv4 网卡修复：写回前清零 `SitePrefixLength`，并将初始化、路由、管道和进程启动错误细化到操作名称及 Win32 错误码。接管失败也会记录在应用日志中。用户已反馈此前失败的 DBX 接管成功；旧日志仍不足以确定原先具体失败的接口。

## Windows 本机构建

两个仓库保持并列：`aTrustHub` 使用 `feat/easyconnect-desktop`，`zju-connect` 使用 `feat/desktop-worker`。两个仓库都需要更新。Hub 使用其 patched module；独立 worker 必须设置 `GOWORK=off`，不要通过 `go work use` 把两个实现混入同一 workspace。安装满足 `go.mod` 要求的 Go 工具链，在 Windows x64 的 PowerShell 7 中进入 `aTrustHub`，逐条运行下面的命令；构建报错时先处理该步，不运行尚未完成的包。

```powershell
New-Item -ItemType Directory -Force .\build\windows-capture\resources, .\build\windows-capture\core | Out-Null
# `go build` 不会自己写 Windows 资源，先写出带应用图标的 .syso，链接后再删掉。
go run .\cmd\appicon -arch amd64 -out .\appicon_windows_amd64.syso
go build -mod=readonly -trimpath '-ldflags=-H=windowsgui' -o .\build\windows-capture\easyconnect-hub.exe .
Remove-Item .\appicon_windows_amd64.syso
# worker 和抓包助手是内部程序，与发布包一致放进 core/。
go build -mod=readonly -trimpath '-ldflags=-H=windowsgui' -o .\build\windows-capture\core\easyconnect-hub-capture.exe ./cmd/app-helper
$previousGoWork = $env:GOWORK
try {
    $env:GOWORK = 'off'
    go -C ..\zju-connect build -mod=readonly -trimpath '-ldflags=-H=windowsgui' -o ..\aTrustHub\build\windows-capture\core\easyconnect-worker.exe ./cmd/easyconnect-worker
    if ($LASTEXITCODE -ne 0) { throw 'worker build failed' }
} finally { $env:GOWORK = $previousGoWork }
Copy-Item .\resources\icon.png .\build\windows-capture\resources\icon.png -Force
Copy-Item .\packaging\windows\test-worker.ps1 .\build\windows-capture\test-worker.ps1 -Force
& .\build\windows-capture\test-worker.ps1
go test -mod=readonly -trimpath -c -o .\build\windows-capture\windows-capture-tests.exe ./internal/wincapture
# 以下进程启动测试须在普通权限 PowerShell 中运行。
.\build\windows-capture\windows-capture-tests.exe '-test.v' '-test.timeout=60s'
```

退出旧版本后，普通双击解压目录中的 `easyconnect-hub.exe`，确认启动日志显示本次测试的版本号。请使用同一个配套包内的 `easyconnect-hub.exe` 以及 `core\` 下的 `easyconnect-worker.exe`、`easyconnect-hub-capture.exe`；`core\` 是内部程序目录，不要手动运行其中的 EXE。助手已内嵌 Wintun DLL。`test-worker.ps1` 使用空配置验证 worker v6 协议，无需登录。

Linux 上交叉编译或 Windows Git Bash 打包，可使用 `bash scripts/package-windows.sh`。默认打发布包 `easyconnect-hub-windows-<arch>`，只放运行必需的程序（根目录的 `easyconnect-hub.exe` 与 `core\` 下的 worker、助手）、说明和许可证；需要真机验收包时设 `EASYCONNECT_BUNDLE_PROFILE=test`，包名带 `-capture` 后缀，额外包含 `windows-capture-tests.exe`、`test-capture.ps1`、`test-worker.ps1`、性能对照脚本和两份模块清单。两种包在归档前都会用 `test-worker.ps1` 跑一遍 worker v6 协议自检。脚本会先用 `cmd/appicon` 生成带图标的资源对象再编译 GUI，所以包里的 `easyconnect-hub.exe` 不再是 Go 的默认图标；三个 EXE 都带 `-s -w`，去掉符号表和调试信息。Windows PowerShell 调用示例：`& "C:\Program Files\Git\bin\bash.exe" .\scripts\package-windows.sh`。脚本已为 worker 的构建和模块清单单独禁用 workspace。

## 系统 TUN 启动

1. 普通权限启动 GUI，登录两个待测 EasyConnect 网关，并确认它们加入统一资源池。
2. 在“网络授权与路由”核对资源、归属和路由预览。相同域名必须显式设置默认 DNS 归属；裸 IP 同时属于多个业务时默认报冲突。
3. 点击 **系统 TUN**，按需批准助手 UAC。等待“关闭系统 TUN”出现，再测试受管资源。
4. 新模式覆盖系统中命中资源路由的 IPv4 TCP；已有按软件 Job 绑定仍优先。B 断开时保留其归属防止错误回退；新代次增量登记，不重启 A。
5. 停止后检查日志与网络差量。若出现“重试清理”，先处理清理错误；外部修改的代理/NRPT 配置会被保留并报告，不强行覆盖。

新模式本次启动默认关闭，不自动恢复上次开关；显式启用它会关闭旧 aTrust 模式的自动恢复意图。助手异常退出由恢复进程处理拥有的策略，未过期映射池记录跨进程保留，不能分配给其他身份。

## 与 v2rayN 等工具共存

- 本应用只添加授权资源的具体路由，原网络出口可以继续经过其他 TUN/Tailscale。两个程序同时运行的路由、DNS 及开关顺序仍需按本机配置验证。
- Windows 系统代理是一个共享设置，两个程序不能同时占用它。若另一个程序改写代理地址，Hub 会取消自己的“系统代理”状态并保留新设置，退出时也不关闭别人的代理。
- 系统 TUN 与第三方系统代理可以同时开启。应用若把内网目标先交给第三方 HTTP/SOCKS/PAC，该目标就可能不经过本机的资源路由；应在第三方代理中为内网设置绕过，或让该应用显式使用 Hub 的统一入口。程序不会自动更改第三方分流规则。
- 「启动 / 登录后自动恢复应用接管」目前仅在 Linux 提供。Windows 网络助手按会话通过 UAC 启动，自动恢复会每次都弹管理员授权，因此仍请手动开启系统 TUN。
- 第三方 TUN 的 DNS 劫持/严格 DNS 策略可能影响内网 NRPT；IP 连通不等于域名链路通过，须分别使用运行中 DNS 诊断和实际应用验证。

## 按软件接管启动

1. 解压完整 ZIP 到一个目录，不要只拷贝单独的 EXE。
2. 普通双击 `easyconnect-hub.exe`。不要“以管理员身份运行”主界面。
3. 添加 EasyConnect 接入点，连接后在界面输入当前验证码或动态口令。
4. 打开“本机软件”，添加“软件 TCP 接管”，选择程序的 `.exe`。开始菜单列表支持能解析为 EXE 的桌面软件；无法解析时手动选择程序。
5. 保存工作、退出该软件的已有实例，然后点击启动。系统 UAC 仅提升网络助手，软件本身保持普通权限。
6. 首次先测试一个浏览器或数据库工具。停止接管或断开 VPN 会保留软件进程；再次启用需退出软件并重新启动。

多个 VPN 代次、系统模式和按软件模式共用一个助手、Wintun 和包栈。撤销 B 不会重建 A 的网络环境。一个运行时最多保留 16 个映射池；未发布的池可立即释放，已发布的池等待最后承诺 TTL 结束且相关连接关闭后回收。`.4` 修复重连后旧代次未撤销导致的池耗尽；合法保留的池用满时仍明确拒绝新登记。

## 更新与移除

Windows 使用便携包，网络助手按会话通过 UAC 启动，不安装常驻 Windows 服务。更新前关闭系统 TUN 和按软件接管，确认清理完成，再从托盘退出旧 GUI，解压新包到独立目录运行。不要覆盖正在运行的 EXE，也不要只替换其中一个或漏掉 `core\` 目录。

移除时先按同样顺序停止接管并退出；确认 Hub 网卡、路由和 NRPT 已清理后，可删除解压目录。用户数据独立保存在 `%APPDATA%/connect-hub`，删除便携包会保留账号和配置；系统恢复记录清理未完成时，应保留配套程序进行重试。

软件只会在接管规则确认就绪后启动。最后一个软件停止接管后，资源路由和内网域名策略会撤回；若本次会话启用了内网域名，助手和映射地址通道会保留到断开 VPN，以保持重启软件时的域名映射一致。

等待 UAC 时可以取消启动。Windows 的授权提示可能仍显示，请关闭该提示再重试；稍后批准旧提示也不会启动软件或安装网络规则。规则操作已经发出时，停止会等待该次操作完成并撤回，避免影响同一 VPN 下其他软件。

## 网关证书提示

遇到“网关证书的域名字段格式不兼容”时：

1. 点击接入点错误卡片上的 **查看网关证书**。程序自动读取证书并计算 SHA256，无需运行命令查找指纹。
2. 核实接入地址、证书来源和指纹后，勾选 **我已核实网关来源，信任此证书**。
3. 点击 **信任并重试连接**，随后输入图形验证码或动态口令。

编辑接入点 → 高级选项也有 **读取网关证书…**。此入口确认后只填入编辑框，保存接入点后才生效。
读取只做 TLS 握手，不发送账号密码，不会自动信任。首次请通过管理员或其他可信渠道核实；证书名称和颁发者由对端提供。
已保存的指纹只作用于当前接入点。之后证书不一致会停止连接并显示新旧指纹，核实换证后才能替换。
如提示核心不支持读取，请重新构建或替换 `core\easyconnect-worker.exe`，只更新 GUI 无法添加这个命令。

## 本机自测

在普通 PowerShell 中进入解压目录，执行：

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\test-capture.ps1
```

这个脚本只对本次 PowerShell 设置执行策略，不修改全局执行策略。测试使用专用子进程、loopback 和内存网络栈，不登录 VPN、不修改系统路由/DNS、不关闭已有软件。结果保存在 `capture-selftest.txt`。

验证内容：worker v6 IPC、进程组和取消、可信进程归属、TCP 元组、停止后软件存活、共享请求取消、多会话登记、规则差量回滚、清理失败重试、映射退休、TCP 数据和半关闭，以及独立栈的 UDP 测试。生产 NRPT 脚本测试替换全部 DNS cmdlet，IP Helper 测试不创建网卡。栈级 UDP 测试不代表 VPN 业务 UDP 支持；自测不验证真实 UAC、Wintun、NRPT 或 VPN。

## 实机验收

以下各项需要记录本次构建号、起止时间与实际结果。旧版 DBX 成功反馈保留为历史记录，新系统模式需重新验证。

- 已选软件访问一个允许测试的内网网页或数据库；项目连接记录应出现对应目标。
- 未选软件的普通上网、本地开发服务和已有 Tailscale 目标保持原路径。
- 同一目标分别从已选和未选软件连接，验证选择生效。
- 测试软件正常退出、只退出启动父进程但子进程继续运行、停止接管、断开 VPN、拒绝 UAC。
- 两个软件同时使用时，停止或取消其中一个，另一个仍能访问；停止最后一个软件后，资源路由和本应用的 NRPT 策略撤回。
- 退出后检查仅本应用的 `ECH-*` 适配器和 `EasyConnectHub:<会话ID>` DNS 策略是否清理；其他软件的路由和 DNS 策略保持原状。
- 系统模式下 A/B 各自专属资源、同名冲突、同真实 IP 映射、B 断开/重连与新增 B 失败；A 的现有连接保持可用。
- UAC 拒绝、切网、休眠、GUI/助手异常退出及重启恢复，记录 NRPT 和路由的前后差量。

## 当前限制

- 按软件接管仅接管 IPv4 TCP；系统 TUN 的 UDP 试验不扩展按软件接管或显式代理。已知 IPv6 资源会拒绝启用。普通公网流量不安装默认接管路由。
- 按软件模式只绑定本应用新启动且确认属于 Job Object 的进程；系统模式按资源捕获，不要求为每个软件建立 Job。
- 路由按目标地址捕获，未选进程访问同一目标也会先经过助手，再按原接口转发。该原接口可以是 Tailscale。
- 每次捕获配置最多覆盖 1048576 个 IPv4 地址；拒绝默认/过宽路由、本机接口、回环、链路本地和网关控制地址。与已有等长或更具体路由或外部 NRPT 冲突时拒绝启动，授权列表仍完整展示。
- 内网域名经共享 NRPT 和统一归属选择器解析；超时失败不回退公网。系统范围内未选软件也可能收到短期映射地址，助手按原始身份处理。应用自行 DoH 或旧 IPv6 缓存不在 DNS 接管保证范围。
- 映射保留计入已承诺 TTL、在途发布和活跃引用；退役地址不会绑定到新身份。Windows 在发布确认前持久化退休池期限，重启后继续避让。异常退出恢复与断电后清理仍需实测，不会在系统启动时自动运行。
- 当前 aTrust 会话尚不具备新系统模式所需的域名映射能力；包含这类资源时会拒绝启用，可继续使用显式代理或旧 aTrust 模式。
- 当前为解压测试包，未实现常驻安装服务、签名安装器或自动更新。

## 开源复用

沿用 aTrustHub 的 GUI、软件项目与代理入口；zju-connect 的认证、会话、资源规则与隧道；sing-tun 的 Wintun 适配；同一依赖树中的 gVisor 网络栈及 sing 的 socket 查询。gVisor 适配层用于兼容现有依赖版本，不自行实现 TCP/IP。许可证位于 `LICENSES/`，模块版本位于 `*-modules.txt`。
