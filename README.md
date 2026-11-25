# Codex-Proxy

**给 Codex Windows 桌面版与 Codex CLI 的透明进程代理。** 使用你的 HTTP / SOCKS5 代理，无需 TUN、管理员权限或系统代理切换。只处理指定的 Codex 进程与显式允许的子进程，本机 IPC、MCP 与 OAuth 回环连接保持直连。

Windows x64 · Visual Studio 2022 · C++17 · `/MT` · BSD-2-Clause

## 功能特性

- 原生 Win32 桌面启动器：零控制台黑框，支持 Microsoft Store/MSIX 和普通安装目录。
- CLI 包装器：挂起创建、注入、等待就绪后恢复；保留 TUI、管道、JSON 输出、MCP stdio 与退出码。
- CLI `tdh.dll` 静态侧载和非 MSIX `version.dll` 转发，直接运行原生 `codex` 也可加载核心。
- SOCKS5 / HTTP CONNECT，用户名密码认证，FakeIP、IPv4/IPv6 CIDR、通配域名、端口和协议分流。
- SOCKS5 UDP Associate、失败退避和 block/direct 降级，适配 QUIC/HTTP3。
- WinHTTP 系统代理发现屏蔽；`GetAddrInfoExW` 原生异步 DNS、ConnectEx 与 IOCP 完成处理。
- 按日文件日志与不可写回退，核心与正常包装流程不向 stdout 写诊断内容。
- 安装/修复/卸载与只读 Doctor；离线中英双语配置编辑器。

## 桌面版 MSIX 与 CLI 工作原理

```text
CodexDesktopLauncher.exe / codex-proxy.exe
  └─ CREATE_SUSPENDED → 注入 codex_proxy.dll → 等待 Ready → ResumeThread
       ├─ ChatGPT.exe 主进程：默认网络 Hook + 子进程传播
       ├─ ChatGPT.exe NetworkService：网络 Hook + 子进程传播
       ├─ codex.exe / code-mode / computer-use / extension-host：网络 + 传播
       └─ renderer / gpu / crashpad / 其它 utility：跳过

远程连接 → 按策略进入 HTTP / SOCKS5 隧道
127.0.0.1 / ::1 / localhost / 本机网卡地址 → 原生 API 早期旁路
```

MSIX 包 `OpenAI.Codex` 的 `WindowsApps` 安装目录保持只读。启动器在包外保存核心 DLL，通过 AppExecutionAlias 或包内主程序挂起启动并注入，不向包目录复制文件。包定位使用 [GetPackagesByPackageFamily](https://learn.microsoft.com/en-us/windows/win32/api/appmodel/nf-appmodel-getpackagesbypackagefamily) 与 [GetPackagePathByFullName](https://learn.microsoft.com/en-us/windows/win32/api/appmodel/nf-appmodel-getpackagepathbyfullname)。

CLI 垫片必须放在**真正的原生 `codex.exe` 同目录**，不是只有 `codex.cmd` 的 npm 脚本目录。`tdh.dll` 静态依赖核心，Bootstrap 不等待、不阻塞 Loader Lock，系统 TDH 导出延迟转发。包装器则显式等待 Hook 就绪，保证新建目标的首个请求已经受控。直接侧载存在后台初始化时间窗；需要严格首请求保障时使用包装器。

`Local\CodexProxy_Hooks_<pid>` 防止侧载与注入副本重复安装 Hook。`Local\CodexProxy_Ready_<pid>` 是初始化完成事件；启动器还检查 Hook 所有权，不能把“文件加载了”误认为“代理已启用”。任意 `--exec` 目标通过短期 PID 请求获得本次启动授权，不扩大默认子进程名单。

## 快速安装与使用

1. 解压 `codex-proxy-win-x64.zip`，先启动本地 HTTP/SOCKS5 代理。
2. 双击 `scripts\setup.bat`，确认部署。脚本探测 7897、7890、10808、10809、2080，以及系统代理和代理环境变量；通过真实协议应答判断 SOCKS5/HTTP。
3. 使用桌面或开始菜单快捷方式 **「Codex (代理)」**。默认安装位置为 `%LOCALAPPDATA%\codex-proxy`。
4. CLI 安装成功后直接运行 `codex`；也可使用完整路径的 `codex-proxy.exe`。安装器不修改 PATH。

无交互安装、跳过 CLI 侧载：

```powershell
.\scripts\doctor.ps1 -Action Install -Yes
.\scripts\doctor.ps1 -Action Install -SkipCliShim -Yes
```

已有 `config.json` 一律保留。没有探测到代理时，会明确提示初始示例端口 7897 尚未验证；先编辑配置再启动。需要认证的代理应补充凭据。脚本不结束或注入当前运行的应用。

### CLI 包装器

```powershell
.\codex-proxy.exe --help
.\codex-proxy.exe --version
.\codex-proxy.exe exec --json "Explain this repository"
.\codex-proxy.exe --config C:\configs\proxy.json --exec C:\tools\codex.exe app-server
.\codex-proxy.exe --config C:\configs\proxy.json --attach 12345
.\codex-proxy.exe -- --config 'model="..."'
```

包装器选项写在 `--exec <exe>` 之前；目标之后的参数全部透传。普通 Codex 参数遇到与包装器冲突的名字时，先写 `--`。`--help` / `--version` 输出到 stderr；错误诊断也只写 stderr/文件，stdout 留给目标程序。

原生 CLI 探测优先级：

1. `CODEX_PROXY_TARGET_EXE`；显式路径无效时报告错误。
2. `%APPDATA%\npm\node_modules\@openai\codex\node_modules\@openai\codex-win32-x64\vendor\x86_64-pc-windows-msvc\bin\codex.exe`，以及旧版/同级 vendor 布局。
3. pnpm 全局目录和 `.pnpm` 原生包、`BUN_INSTALL` 与 `~\.bun` 全局目录。
4. PATH 中的 `codex.exe`。
5. `%LOCALAPPDATA%\codex\codex.exe`。

包装器先把新建进程加入 `KILL_ON_JOB_CLOSE | BREAKAWAY_OK` Job，再完成注入和就绪握手。注入、配置、Job 或恢复失败时结束本次新建目标，返回 125。目标正常退出时透传其原始退出码。Ctrl+C 交给目标处理；包装器被结束时清理仍在 Job 中的后代，显式 breakaway 的工具可以脱离。

`--attach` 仅接管之后的新连接，已经建立的 TCP/TLS 连接不会迁移。已启用 Hook 的进程不重复安装；配置变更需要重启进程。热注入的配置通过 PID 请求传递，不依赖修改运行中进程的环境。

### 桌面启动器

```powershell
.\CodexDesktopLauncher.exe
.\CodexDesktopLauncher.exe --config C:\configs\proxy.json
.\CodexDesktopLauncher.exe --target C:\Apps\Codex\ChatGPT.exe --restart
.\CodexDesktopLauncher.exe --attach
.\CodexDesktopLauncher.exe --dry-run
.\CodexDesktopLauncher.exe --target C:\Apps\Codex\ChatGPT.exe --sync-local
```

自动定位顺序：`--target` → 同目录 `desktop_path.txt` → `%LOCALAPPDATA%\Microsoft\WindowsApps\chatgpt-desktop.exe` → MSIX 家族 `OpenAI.Codex_2p2nqsd0c76g0` 的 `app\ChatGPT.exe` / `app\Codex.exe` → `%LOCALAPPDATA%\Programs\Codex` → 首次文件选择器。选择结果保存为 `desktop_path.txt`；启动器目录不可写时回退到用户安装目录。

已有桌面实例的处理：

- 已加载核心且就绪：唤醒窗口；有应用参数时，通过受控启动路径交给单实例应用转发。
- 正在直连：默认显示中英双语选择框，Yes=关闭并重启代理模式，No=热注入主进程、NetworkService 与目标引擎子进程，Cancel=退出。
- `--restart` 明确授权关闭该桌面进程树中的 Codex/Chromium 进程；先请求关闭窗口，超时后结束仍存活的目标进程。请先保存操作。
- `--attach` 不重启窗口，只处理目标进程族；旧连接保持原状态，需要完全切换时使用重启。
- `--dry-run` 只把候选路径与运行态写入日志/可用 stderr，不弹框、不选择文件、不注入、不启动或结束目标，也不写应用配置。

AppExecutionAlias 创建失败时，自动尝试已定位的 MSIX 包内主程序。非 MSIX 的可写目录可显式使用 `--sync-local` 增量同步 `version.dll`、核心和配置，保留已有 config.json；被替换的 DLL 备份到 `.codex-proxy-original`。这类可选目录副本独立于安装器管理；恢复时关闭应用，再还原备份或移除本项目副本。WindowsApps 始终跳过同步。

## 配置说明

配置查找优先级：

1. `CODEX_PROXY_CONFIG` 指向且存在的文件（包装器 `--config` 设置子进程环境）。
2. 核心 DLL 同目录 `config.json`。
3. 核心 DLL 同目录受管文件 `codex-proxy.config-path` 指向的现存配置（UTF-8 绝对路径）。
4. `%LOCALAPPDATA%\codex-proxy\config.json`。

不搜索当前工作目录。选中文件无效时不会继续回退其他文件。配置是进程启动时的快照，修改后重启。默认端口白名单仅代理 80/443，空数组代理所有端口；`proxy.port=0` 明确表示全部直连，并关闭 FakeIP 与 WinHTTP 屏蔽。

安装器部署 CLI 垫片时会受管写入 `codex-proxy.config-path`，因此自定义 `-Destination` 也能共享该目录的配置；卸载时按文件哈希移除，原有文件会先备份并在卸载时恢复。定位文件不包含代理密码。热注入选中的配置也会通过子进程 PID 启动请求沿子进程树传递，优先于子进程继承的环境变量。

打开 `config-web.html`，导入配置、编辑并导出 config.json，然后替换实际配置文件。编辑器不上传数据、不发请求、保留未知配置字段；预览隐藏密码，导出的文件包含真实凭据。浏览器页面不会自动写入安装目录或热更新进程。

| 配置 | 默认值与含义 |
| --- | --- |
| `proxy.host/port/type` | `127.0.0.1:7890`，`socks5`；也支持 HTTP CONNECT |
| `proxy.username/password` | 可选认证；配置为本地明文，日志不记录密码和载荷 |
| `proxy.ignore_system_proxy` | true；屏蔽 WinHTTP 的 IE/自动代理发现，避免系统代理形成另一条链路。显式代理环境变量仍由应用自身处理 |
| `desktop_host_network_hooks` | **true**；ChatGPT 主进程也启用网络 Hook。false 恢复为主进程仅传播；NetworkService 仍启用网络 Hook，非网络 Chromium 子进程始终跳过 |
| `fake_ip.enabled/cidr` | true，`198.18.0.0/15`；共享环形池，支持 /15…/30，避免多个进程独立分配同一地址 |
| `timeout.connect_ms/send_ms/recv_ms` | 各 5000ms，1…300000；兼容原字段 connect/send/recv |
| `rules.allowed_ports` | `[80,443]`，空数组表示所有端口 |
| `rules.dns_mode` | direct；控制原始目标端口 53 的 direct/proxy，不表示关闭 FakeIP 域名解析 |
| `rules.ipv6_mode` | proxy；也支持 direct/block。v4-mapped IPv6 按 IPv4 处理 |
| `rules.udp_mode` | auto；SOCKS5 下尝试 UDP Associate，HTTP 下使用 fallback；可选 proxy/direct/block |
| `rules.udp_fallback` | block；可选 direct。Associate 失败退避 60 秒，不支持 SOCKS5 UDP 分片 |
| `rules.routing` | 默认私网直连；支持 IPv4/IPv6 CIDR、域名 `*` / `?` / 后缀、端口/范围、tcp/udp、顺序/数字优先级 |
| `target_processes` | codex.exe、chatgpt.exe、codex-code-mode-host.exe、codex-computer-use-swift.exe、extension-host.exe；完整基名、大小写不敏感 |
| `child_injection` | true 或 `{ "enabled": true, "exclude": [] }`；仅传播到名单进程，空名单不会注入全部进程，拒绝 inherit 模式 |
| `logging.enabled/level` | true / info；支持 debug/info/warn/error |
| `traffic_monitor.enabled` | false；开启后只记录方向、socket 和字节数 |

回环与本机地址的早期旁路优先于分流规则、端口、IPv6 和 UDP 策略；OAuth 1455/1457、本地 MCP/IPC 不需要端口特例。`powershell.exe`、`pwsh.exe`、`cmd.exe`、`git.exe`、`node.exe`、`python.exe` 默认不注入，除非用户明确把它们列入目标名单。

分流示例（地址/域名为 OR，与端口和协议为 AND；无地址条件可用于纯端口规则）：

```json
{
  "rules": {
    "routing": {
      "enabled": true,
      "priority_mode": "number",
      "default_action": "proxy",
      "use_default_private": true,
      "rules": [{
        "name": "internal-api",
        "enabled": true,
        "action": "direct",
        "priority": 10,
        "domains": ["*.internal.example"],
        "ip_cidrs_v4": ["10.20.0.0/16"],
        "ip_cidrs_v6": ["fd00:1234::/32"],
        "ports": ["8000-9000"],
        "protocols": ["tcp"]
      }]
    }
  }
}
```

## Doctor 体检、修复与卸载

```powershell
.\scripts\doctor.ps1 -Action Check
.\scripts\doctor.ps1 -Action Check -TestOpenAI
.\scripts\doctor.ps1 -Action Check -TestChatGPT
.\scripts\doctor.ps1 -Action Repair -Yes
.\scripts\doctor.ps1 -Action Install -ProxyHost 127.0.0.1 -ProxyPort 7897 -ProxyType socks5 -Yes
.\scripts\doctor.ps1 -Action Uninstall -Yes
.\scripts\doctor.ps1 -Action Uninstall -Purge -Yes
```

`doctor.bat` 可传相同参数。Check 只读配置、文件、模块和日志，主动探测代理协议，不安装、注入、重启或改系统设置。`-TestOpenAI` 是显式可选联网检查：通过代理建立到 `api.openai.com` 的隧道，验证 TLS 后请求 `/v1/models`，不携带 API Key。`-TestChatGPT` 以相同方式检查 `chatgpt.com/backend-api/models`，不携带登录信息。401/403 只能证明收到 HTTP 响应，不代表账号、模型或地区权限正常。

Install / Repair 部署便携文件、保留配置、创建桌面与开始菜单快捷方式，并向探测到的原生 CLI 目录放入两个垫片。`-SkipCliShim` 跳过该步骤；`-SourceDir`、`-Destination`、`-CliExe` 可指定路径，`-ShortcutRoot` 供隔离部署/自动化测试使用。

安装清单记录每个受管文件的路径、SHA-256 与原文件备份。Uninstall 只移除仍匹配本项目记录的 DLL，恢复被替换的原 DLL；被用户改动的文件会保留并提示。默认保留 config.json、日志与安装记录；`-Purge` 在验证目录归属后删除整个安装目录。安装器不自动停止使用 DLL 的进程，文件被占用时请关闭相关应用再操作。CLI 更新可能迁移原生目录，更新后重新运行 Repair。

### 常见问题

| 现象 | 检查与处理 |
| --- | --- |
| 启动失败 / 返回 125 | 查看日志与 stderr；核对同目录核心 DLL、有效配置、x64 目标与权限；配置/注入失败不会恢复本次新建目标 |
| 代理隧道被拒绝 / 超时 | 先运行 Doctor；核对实际监听端口与协议。HTTP、SOCKS5 端口不可混用，认证需要真实凭据 |
| CLI 仍读取另一份配置 | 检查 CODEX_PROXY_CONFIG、原生 exe 旁的 config.json 与 codex-proxy.config-path；Doctor 会展示 CLI 实际配置查找结果 |
| 打开了既有直连窗口 | 选择重启或热注入；只启动另一个桌面实例可能触发应用单实例转交，必须检查原进程状态 |
| 修改配置后没有变化 | 配置不会热更新；重启已有进程。--attach 不迁移旧连接，也不重配已生效实例 |
| HTTP 代理不支持 UDP / QUIC 失败 | 默认 fallback=block 可促使应用尝试 TCP；需要 UDP 时使用支持 Associate 的 SOCKS5 服务 |
| 网络服务能连，桌面主进程请求不通 | 确认 desktop_host_network_hooks=true；用日志核对宿主 scope，检查是否误用了旧版 DLL |
| 包目录不可写 | MSIX 不使用 DLL 文件复制；使用桌面启动器，不需要管理员权限 |
| 找不到日志 | `<dll_dir>\logs\proxy-YYYYMMDD.log` → `%LOCALAPPDATA%\codex-proxy\logs` → `%TEMP%\codex-proxy-logs` |

日志按本机日期追加，多进程写入串行化，不含网络载荷。FakeIP 池回绕后旧地址可能过期；不应让应用永久缓存 FakeIP。核心固定在进程内以保证 Hook 与未完成 I/O 的生命周期，不支持热卸载。

## 编译、测试与打包

需要 Python 3、VS 2022 的 C++ x64 工具链、Windows SDK 和 CMake/Ninja。脚本兼容 Windows PowerShell 5.1 与 PowerShell 7：

```powershell
.\build.ps1 -Config Release -RunTests -Package
.\build.ps1 -Config Release -Clean -RunTests -Package
.\build.ps1 -Config Debug -VisualStudio D:\VisualStudioIDE -SdkRoot C:\path\to\WindowsSDK
```

默认使用 `D:\VisualStudioIDE`；Windows SDK 可从注册表或项目 `.deps\winsdk\Windows Kits\10` 发现。构建只设置子进程环境，不修改全局 SDK 配置。Release 使用 `/MT`，Debug `/MTd`。

发布产物：

```text
output/codex-proxy-win-x64/
  CodexDesktopLauncher.exe  codex-proxy.exe
  codex_proxy.dll           version.dll          tdh.dll
  config.example.json       config-web.html
  README.md                LICENSE.txt          AUTHORS.txt
  UPSTREAM.txt             manifest.json        SHA256SUMS.txt
  scripts/                 docs/                validation/
output/codex-proxy-win-x64.zip
output/SHA256SUMS.txt
```

发布包不预置生效的 config.json，安装时探测生成，避免覆盖已有配置。包内 SHA 清单使用包内相对路径；外部清单覆盖目录内文件及 ZIP。测试可直接使用 CMake `-DBUILD_TESTS=ON`；浏览器 QA 在已安装 Python Playwright 与 Chromium 时自动加入，页面本身没有这些运行依赖。

测试覆盖 Phase 1 核心、宿主开关两种模式、两个启动器的纯逻辑、真实挂起注入与 SOCKS5/HTTP 转发、管道二进制透传、热注入、退出码、Job 后代清理、桌面 dry-run、PowerShell AST、隔离安装/修复/卸载和浏览器配置编辑。所有会修改文件、启动或结束进程的验收均使用临时目录和测试程序；当前用户桌面应用仅做只读检查。

## 致谢与许可证

本项目改编自 [yuaotian/antigravity-proxy](https://github.com/yuaotian/antigravity-proxy) 的网络、路由、Hook、注入和版本转发基础，并参考其 ACP/桌面启动器与 Doctor 工作流。参考提交记录在 `UPSTREAM.txt`，所有适用的版权与免责声明保留于 `LICENSE.txt` 和 `AUTHORS.txt`。

- antigravity-proxy：Copyright (c) yuaotian and antigravity-proxy contributors，BSD-2-Clause。
- MinHook：Copyright (C) 2009-2017 Tsuda Kageyu，BSD-2-Clause；原作者名单保留。
- HDE：Copyright (c) 2008-2009 Vyacheslav Patkov，原许可保留。
- nlohmann/json：Copyright (c) 2013-2026 Niels Lohmann，MIT。

分发二进制时请一并分发上述版权文件。Phase 1 历史记录与旧 README 保留在 `docs/`；旧交付包不被 Phase 2 打包覆盖。Codex-Proxy 不是 OpenAI 官方产品。
