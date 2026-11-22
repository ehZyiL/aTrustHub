# Connect Hub (桌面端)

[![Build & Release](https://github.com/ehzyil/aTrustHub/actions/workflows/build.yml/badge.svg)](https://github.com/ehzyil/aTrustHub/actions/workflows/build.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.27+-00ADD8?logo=go)](https://go.dev/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey)](https://github.com/ehzyil/aTrustHub/releases)

**Connect Hub**（原 aTrustHub）是聚合多套企业/高校 VPN 接入点的跨平台桌面客户端，支持在一个窗口内**同时登录并保持多个深信服 aTrust 零信任网关与 EasyConnect VPN 接入点**，并按资源归属实现智能分流。

> [!NOTE] 文档说明与免责声明
> 本项目的说明文档与开发手册主要由 **AI 辅助分析与整理生成**。**若文档表述与程序实际运行逻辑、代码实现存在细微出入或更新滞后，请一律以最新源代码（Source Code）及实际运行时表现为主**。欢迎提交 PR 协助修正文档。

---

## 核心特性

- **多网关并发**：同时连接多个不同单位/客户的 aTrust 或 EasyConnect 网关，互不干扰，隧道独立（*注：aTrust 为上游原有实现，本分支 Fork 后未进行实机测试*）。
- **全认证支持**：账号密码、企业微信扫码/客户端确认、短信验证码、图形验证码及浏览器第三方 SSO（CAS / IDaaS）。
- **按需网络接管**：
  - **Windows 平台**：支持「不使用」（纯本地监听）、「系统代理」（全局系统代理托管）与「应用接管」（Wintun 驱动与私有网段/NRPT 路由，透明访问内网）三种互斥模式；
  - **Linux 平台**：支持「不使用」（纯本地监听）与「应用接管」（Linux 原生 TUN 资源路由与 cgroup 流量管控），Linux 平台不提供系统代理托管；
  - **独立与统一入口**：每个在线接入点提供独立 SOCKS5 端口，同时提供具备故障转移、延迟优先与哈希策略的统一聚合入口。
- **证书指纹核验**：针对自签名或格式异常的网关证书，提供安全的 SHA-256 指纹核验与信任绑定。
- **自愈与资源保障**：周期保活（Keepalive）、失效自动重连、健康度探测与退出完全清理，杜绝网络垃圾残留。
- **内存深度优化**：支持后台闲置工作集修剪（Working Set Trimming），显著降低空闲常驻内存占用。

> [!WARNING] 协议支持与测试状态说明
> 本项目代码库继承并保留了上游原版对 **深信服 aTrust 零信任网关** 的完整支持代码。但自当前分支从上游 Fork 以来，所有功能迭代与实机验证均集中在 **EasyConnect 网关**、软件抓包接管与全系统 TUN 模式上，**aTrust 协议在当前分支未做实机回归测试**。使用 aTrust 时若遇到问题，欢迎提交反馈。

---

## 软件功能界面展示

### 1. 多接入点管理主界面
一个窗口统一管理多网关，实时展示连接状态、延迟与独立代理端口：
![多接入点管理](docs/assets/screenshot.png)

### 2. 顶栏接管模式快速切换
直观的顶栏胶囊下拉菜单，可在 **「不使用」**、**「系统代理」**、**「应用接管」** 间就地切换：
![接管模式切换](docs/assets/screenshot-capture-menu.png)

### 3. 本机软件接管（进程级定向分流）
将特定工具关联至指定网关，免配代理直接互通：
![本机软件接管](docs/assets/screenshot-localapps.png)

### 4. 网关资源与私有网段
直观呈现下发的网段资源并支持一键连通性测试：
![网关资源列表](docs/assets/screenshot-resources.png)

---

## 相关文档索引

- 开发者完整手册：[DEVELOPMENT.md](DEVELOPMENT.md)
- Windows 快速入门手册：[WINDOWS-QUICKSTART.md](WINDOWS-QUICKSTART.md)
- Linux 快速入门手册：[LINUX-QUICKSTART.md](LINUX-QUICKSTART.md)
- Windows 底层技术实现白皮书：[WINDOWS-IMPLEMENTATION.md](WINDOWS-IMPLEMENTATION.md)
- 历史设计稿与架构演进记录：[docs/greenfield-architecture-2026-11-20.md](../docs/greenfield-architecture-2026-11-20.md)

---

## 本地编译与运行简述

详细编译环境配置与调试流程，请查阅 **[DEVELOPMENT.md](DEVELOPMENT.md)**。

```bash
# 1. 编译特权助手
go build -mod=readonly -trimpath -o build/core/connect-hub-capture ./cmd/app-helper

# 2. 编译独立协议工作进程 (必须切换 GOWORK=off)
(cd ../zju-connect && env GOWORK=off go build -mod=readonly -trimpath -o ../aTrustHub/build/core/easyconnect-worker ./cmd/easyconnect-worker)

# 3. 编译桌面主程序
go build -mod=readonly -trimpath -o build/connect-hub .
```

---

## 开源协议

本项目遵循 [AGPL-3.0 License](LICENSE) 协议。
