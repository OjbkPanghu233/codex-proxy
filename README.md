# Codex-Proxy

让 **OpenAI Codex（Windows 桌面版 + CLI）** 免 TUN 模式、免管理员权限、仅代理自身进程走 SOCKS5 / HTTP 代理。

---

## 安装方式

### 方式一：下载预编译包（推荐）

1. 前往 [Releases](https://github.com/OjbkPanghu233/codex-proxy/releases) 下载最新 `codex-proxy-win-x64.zip` 并解压到任意目录。
2. 先启动本地代理软件（如 Clash / Mihomo / v2rayN 等）。
3. 双击 `scripts\setup.bat`（或在 PowerShell 运行下面命令）完成一键部署：

```powershell
.\scripts\doctor.ps1 -Action Install
```

脚本会自动探测本机代理端口与协议，默认部署到 `%LOCALAPPDATA%\codex-proxy\`，并完成两件事：
- 在桌面和开始菜单创建 **「Codex (代理)」** 快捷方式（用于桌面版）；
- 在原生 `codex.exe` 目录部署侧载垫片 `tdh.dll` + `codex_proxy.dll`（用于 CLI，若不想改动 CLI 目录可加 `-SkipCliShim`）。

**卸载：**

```powershell
.\scripts\doctor.ps1 -Action Uninstall       # 移除快捷方式与 CLI 垫片（保留 config.json）
.\scripts\doctor.ps1 -Action Uninstall -Purge # 彻底删除安装目录
```

### 方式二：从源码编译

环境要求：Windows x64、Visual Studio 2022（C++ 桌面开发）、Windows SDK、Python 3。

```powershell
.\build.ps1 -Config Release -RunTests -Package
```

产物生成在 `output\codex-proxy-win-x64\` 与 `output\codex-proxy-win-x64.zip`。

---

## 使用方法

### 1. Codex Windows 桌面版

- 双击桌面或开始菜单中的 **「Codex (代理)」** 启动（底层为无黑框的 `CodexDesktopLauncher.exe`，可固定到任务栏替代原版图标）。
- 若 Codex 桌面版此前已用原版图标直连打开，再次点击「Codex (代理)」会弹窗提示选择**重启为代理模式**或**热注入当前进程**（命令行也支持 `--restart` / `--attach`）。
- Microsoft Store 自动更新 Codex 桌面版后**无需重新修补丁**。

### 2. Codex CLI

安装完成后支持两种方式：

- **直接运行（无感模式）**：在任意终端、IDE 或 MCP 中像平时一样直接执行 `codex` 即可走代理。
  - 若执行 `npm update -g @openai/codex` 更新 CLI 后失效，跑一次 `.\scripts\doctor.ps1 -Action Repair` 补回垫片即可。
- **零侵入包装器（不改动 `node_modules`）**：

```powershell
codex-proxy.exe exec "解释这个仓库"
codex-proxy.exe --config C:\path\to\config.json exec "使用临时代理配置"
codex-proxy.exe --exec C:\path\to\codex.exe app-server
```

### 3. 修改代理配置与体检

- **可视化配置**：用浏览器打开 `config-web.html`，修改代理地址、端口、协议（`socks5` / `http`）、账号密码或分流规则，导出覆盖 `%LOCALAPPDATA%\codex-proxy\config.json` 后重启 Codex 生效。
- **一键体检 / 排障**：双击 `scripts\doctor.bat`（只读检查），可查看 Codex 桌面版与 CLI 路径、运行中进程是否已加载代理模块、本地代理端口协议及日志位置。

---

## 关键原理

1. **进程级 Winsock / DNS Hook（免 TUN、不接管系统流量）**
   - `codex_proxy.dll` 基于 MinHook 拦截 `ws2_32.dll` 的连接与 DNS 接口（`connect`、`WSAConnect`、`ConnectEx`、`getaddrinfo`、`GetAddrInfoW`、`GetAddrInfoExW`、IOCP 及 SOCKS5 UDP Associate），将远程流量透明转发到配置的 SOCKS5 / HTTP 代理。
   - **FakeIP（`198.18.0.0/15`）**：DNS 阶段返回虚拟占位地址，连接阶段还原真实域名交给代理端解析，避免本地 DNS 泄漏。
   - **WinHTTP 系统代理屏蔽**：默认启用 `ignore_system_proxy: true`，拦截 `WinHttpGetIEProxyConfigForCurrentUser` / `WinHttpGetProxyForUrl`，防止 `codex.exe` 被 Windows 系统代理绕过或二次代理。
   - **本机严格旁路**：`127.0.0.1`、`::1`、`localhost` 及本机网卡地址强制直连，确保 Codex OAuth 回调（`1455` / `1457`）与本地 MCP/IPC 正常工作。

2. **Windows 桌面版（MSIX 只读包）如何无管理员生效**
   - Codex Windows 桌面版为 Microsoft Store 的 MSIX FullTrust 应用，安装目录 `C:\Program Files\WindowsApps\OpenAI.Codex_*` 只读不可写。
   - `CodexDesktopLauncher.exe` 通过挂起创建（`CREATE_SUSPENDED`）拉起桌面主进程 `ChatGPT.exe`，提前注入 `codex_proxy.dll` 并等待 `Local\CodexProxy_Ready_<pid>` 就绪事件后再恢复运行。
   - 随后通过 `CreateProcessW` / `CreateProcessA` Hook 精准传播到 `ChatGPT.exe`（`NetworkService`）、`codex.exe`（`app-server` / `exec-server`）、`codex-code-mode-host.exe` 等 Codex 引擎进程，同时自动跳过 Chromium renderer/GPU 以及 `powershell.exe` / `git.exe` 等用户工具子进程。

3. **Codex CLI 双入口机制**
   - **无感侧载（`tdh.dll`）**：原生 `codex.exe` 静态导入且不在 Windows `KnownDLLs` 中的 `tdh.dll`。将转发垫片 `tdh.dll` 与 `codex_proxy.dll` 置于 `codex.exe` 同目录，即可在启动时自动加载代理并把原生导出转发至系统 `tdh.dll`。
   - **包装器（`codex-proxy.exe`）**：采用挂起注入 + 就绪等待 + Job 对象清理 + stdio/退出码原样透传，严格保证首包即走代理且不污染 `stdout`（兼容 TUI 与 `codex exec --json`）。

---

## 致谢

- **[yuaotian/antigravity-proxy](https://github.com/yuaotian/antigravity-proxy)**（BSD-2-Clause）：本项目的核心架构、Winsock/FakeIP/路由 Hook 与 Doctor 工具设计均参考并改编自 `antigravity-proxy`。
- **[MinHook](https://github.com/TsudaKageyu/minhook)**（Copyright © 2009-2017 Tsuda Kageyu，BSD-2-Clause）与 **HDE**（Copyright © 2008-2009 Vyacheslav Patkov）：底层 API Hook 引擎。
- **[nlohmann/json](https://github.com/nlohmann/json)**（Copyright © 2013-2026 Niels Lohmann，MIT）：JSON 配置解析库。

本项目采用 **BSD-2-Clause** 开源协议，详见 [LICENSE.txt](LICENSE.txt) 与 [AUTHORS.txt](AUTHORS.txt)。Codex-Proxy 为独立开源工具，与 OpenAI 无官方关联。
