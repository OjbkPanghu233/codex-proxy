<div align="center">

# Codex-Proxy

**让 OpenAI Codex（Windows 桌面版 & CLI）免 TUN 模式也能稳定走代理**

[![Platform](https://img.shields.io/badge/platform-Windows%20x64-0078D6?style=flat-square)](https://github.com/OjbkPanghu233/codex-proxy/releases)
[![Release](https://img.shields.io/github/v/release/OjbkPanghu233/codex-proxy?style=flat-square&color=2ea44f)](https://github.com/OjbkPanghu233/codex-proxy/releases)
[![License](https://img.shields.io/badge/license-BSD--2--Clause-blue?style=flat-square)](LICENSE.txt)

只接管 Codex 进程树 · 无需管理员权限 · 支持 SOCKS5 / HTTP 认证 · 兼容 MSIX 自动更新

</div>

---

## 📦 安装方式

### 方式一：下载预编译包（推荐）

1. 前往 [**Releases**](https://github.com/OjbkPanghu233/codex-proxy/releases) 下载最新版 `codex-proxy-win-x64.zip` 并解压到任意非临时目录。
2. 确保本地代理客户端（Clash / Mihomo / v2rayN 等）已启动。
3. 双击 `scripts\setup.bat`，或在 PowerShell 中执行一键部署：

```powershell
.\scripts\doctor.ps1 -Action Install
```

安装脚本会自动探测本机代理端口与协议，默认部署至 `%LOCALAPPDATA%\codex-proxy\`，并完成：
- **桌面版入口**：在桌面与开始菜单创建 **「Codex (代理)」** 快捷方式；
- **CLI 无感侧载**：向原生 `codex.exe` 目录部署 `tdh.dll` 与 `codex_proxy.dll`（如需跳过，追加 `-SkipCliShim`）。

<details>
<summary>卸载与清理命令</summary>

```powershell
.\scripts\doctor.ps1 -Action Uninstall        # 移除快捷方式与 CLI 垫片（保留 config.json）
.\scripts\doctor.ps1 -Action Uninstall -Purge # 彻底清理安装目录
```

</details>

### 方式二：从源码编译

需要 **Windows x64**、**Visual Studio 2022（C++ 桌面开发）**、**Windows SDK** 与 **Python 3**：

```powershell
.\build.ps1 -Config Release -RunTests -Package
```

构建完成后可在 `output\codex-proxy-win-x64\` 与 `output\codex-proxy-win-x64.zip` 获取完整便携包。

---

## 🚀 使用方法

### 1. Codex Windows 桌面版

- 通过桌面或开始菜单中的 **「Codex (代理)」** 启动（底层为无黑框的 `CodexDesktopLauncher.exe`，推荐固定到任务栏替代原版图标）。
- **单实例智能处理**：若此前已用系统原版图标直连打开 Codex 桌面版，再次点击「Codex (代理)」会弹窗提示选择**重启为代理模式**或**热注入当前进程**（命令行亦支持 `--restart` / `--attach`）。
- **无惧商店更新**：Microsoft Store 自动更新 Codex 桌面版后，无需重新安装或修复补丁。

### 2. Codex CLI

| 模式 | 使用方式 | 适用场景 |
| :--- | :--- | :--- |
| **无感模式**（默认） | 直接在终端、IDE 或 MCP 中运行 `codex` | 日常高频使用，完全零感知 |
| **包装器模式** | 使用 `codex-proxy.exe` 拉起目标进程 | 不改动 `node_modules` 或临时切换不同代理配置 |

```powershell
# 包装器常用示例
codex-proxy.exe exec "解释当前仓库结构"
codex-proxy.exe --config C:\path\to\config.json exec "临时指定其他代理配置"
codex-proxy.exe --exec C:\path\to\codex.exe app-server
```

> [!TIP]
> 执行 `npm update -g @openai/codex` 更新 CLI 后，若无感模式失效，运行一次 `.\scripts\doctor.ps1 -Action Repair` 即可恢复垫片；包装器模式不受 CLI 升级影响。

### 3. 修改配置与一键体检

- **可视化配置**：用浏览器直接打开包内的 `config-web.html`，修改代理地址、端口、协议（`socks5` / `http`）、账号密码及分流规则，导出覆盖 `%LOCALAPPDATA%\codex-proxy\config.json` 后重启 Codex 生效。
- **状态体检**：双击 `scripts\doctor.bat`（只读检查），可一站式查看桌面版/CLI 探测路径、运行中进程是否已加载代理模块、代理端口协议识别结果及日志文件位置。

---

## ⚙️ 关键原理

```text
CodexDesktopLauncher.exe / codex-proxy.exe
  └─ CREATE_SUSPENDED ─▶ 注入 codex_proxy.dll ─▶ 等待 Ready 就绪 ─▶ ResumeThread
       ├─ ChatGPT.exe（主进程 & NetworkService）  ──▶ 网络 Hook + 子进程传播
       ├─ codex.exe / code-mode / extension-host  ──▶ 网络 Hook + 子进程传播
       └─ renderer / gpu / powershell / git       ──▶ 自动跳过，零干扰

远程流量 ──▶ FakeIP 还原域名 ──▶ SOCKS5 / HTTP 代理隧道
本机回环 ──▶ 127.0.0.1 / ::1 / localhost（含 OAuth 1455/1457 与本地 MCP）──▶ 原生直连旁路
```

- **进程级 Winsock / DNS 拦截（免 TUN）**
  `codex_proxy.dll` 基于 MinHook 拦截 `ws2_32.dll` 的 TCP/UDP 连接、异步 IOCP（`ConnectEx`）及同步/异步 DNS（`getaddrinfo`、`GetAddrInfoW`、`GetAddrInfoExW`），仅代理当前进程树，不改动系统路由表，也不影响本机其他软件。
- **FakeIP 与 WinHTTP 屏蔽**
  DNS 阶段分配 `198.18.0.0/15` 虚拟地址，连接阶段还原真实域名交由代理端解析，杜绝本地 DNS 泄漏；默认启用 `ignore_system_proxy: true`，屏蔽 `WinHttpGetIEProxyConfigForCurrentUser` / `WinHttpGetProxyForUrl`，避免 `codex.exe` 被 Windows 系统代理绕过或二次代理。
- **MSIX 桌面版免权限适配**
  Microsoft Store 分发的 `OpenAI.Codex` 位于只读目录 `C:\Program Files\WindowsApps\`，无法直接投放 `version.dll`。桌面启动器改为从包外挂起创建主进程并注入核心 DLL，既不修改受保护目录，又天然免疫商店自动更新。
- **CLI 双入口设计**
  原生 `codex.exe` 静态导入且不在 Windows `KnownDLLs` 中的 `tdh.dll`，因此可通过放置 `tdh.dll` 转发垫片实现无感侧载；同时提供 `codex-proxy.exe` 包装器，以挂起注入、Job 进程树清理与纯净 `stdout` 透传兼顾 TUI 与 `codex exec --json` 自动化场景。

---

## 🙏 致谢

本项目深受以下优秀开源项目启发并基于其成果构建，谨此致谢：

- [**yuaotian/antigravity-proxy**](https://github.com/yuaotian/antigravity-proxy)（BSD-2-Clause）—— 本项目的核心架构、Winsock/FakeIP/分流 Hook 与 Doctor 工具设计均参考并改编自该项目。
- [**MinHook**](https://github.com/TsudaKageyu/minhook)（Copyright © 2009-2017 Tsuda Kageyu，BSD-2-Clause）与 **HDE**（Copyright © 2008-2009 Vyacheslav Patkov）—— 轻量稳定的 Windows API Hook 引擎。
- [**nlohmann/json**](https://github.com/nlohmann/json)（Copyright © 2013-2026 Niels Lohmann，MIT）—— 现代 C++ JSON 解析库。

> [!NOTE]
> 本项目遵循 **BSD-2-Clause** 开源协议（详见 [LICENSE.txt](LICENSE.txt) 与 [AUTHORS.txt](AUTHORS.txt)）。Codex-Proxy 为独立开源工具，与 OpenAI 无官方关联。
