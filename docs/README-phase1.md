# Codex-Proxy

Windows x64 进程级 Winsock 代理核心，面向 Codex Windows 桌面版与原生 Codex CLI。支持 SOCKS5、HTTP CONNECT、FakeIP、SOCKS5 UDP Associate 和目标子进程注入。无需 TUN 或管理员权限，不修改系统代理。当前交付范围为 **Phase 1：核心 DLL、侧载垫片、配置和测试**。

本项目基于 [yuaotian/antigravity-proxy](https://github.com/yuaotian/antigravity-proxy) 的 BSD-2-Clause 网络与 Hook 实现改编，保留并扩展其本地目标旁路修复；删除了 Antigravity 更新检查、插件、UI 和自动注入 Node 的兼容分支。

## 构建

需要 Windows x64、Visual Studio 2022 C++ 工具链、Windows SDK、CMake 3.21+。使用 VS 开发者终端：

```powershell
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

本机也可执行 `python tools/build.py`。脚本默认使用 `D:\VisualStudioIDE`，支持 `--vs`、`--sdk-root`、`--config Debug`、`--build-dir`；可识别项目内 `.deps\winsdk\Windows Kits\10`。SDK 路径仅对构建子进程生效。依赖头文件和 MinHook 源码均已包含在仓库中，构建不下载依赖。MSVC 使用 C++17、`/utf-8`、Release `/MT`，Debug `/MTd`。

产物：`codex_proxy.dll`、`version.dll`、`tdh.dll` 与相应导入库。`cmake --install build --prefix output/phase1` 安装 DLL、版权和配置示例，不自动覆盖用户配置。

## 加载与进程边界

| 入口 / 进程 | 行为 |
| --- | --- |
| MSIX 桌面版 | 从外部可写目录注入 `codex_proxy.dll`；不向 WindowsApps 写入文件。挂起启动器属于后续阶段。 |
| 非 MSIX 桌面版 | 在可写应用目录放置 `version.dll` 和 `codex_proxy.dll`，转发系统 version API。 |
| CLI 原生目录 | 在真正的 `codex.exe` 旁放置 `tdh.dll` 和 `codex_proxy.dll`。npm 的脚本目录与原生 exe 目录可能不同。 |
| `ChatGPT.exe` 主进程 | 仅安装 CreateProcessA/W 传播 Hook。 |
| `ChatGPT.exe` NetworkService | 精确匹配 `--type=utility --utility-sub-type=network.mojom.NetworkService`，启用网络与传播 Hook。 |
| Chromium renderer / gpu / crashpad / 其它 utility | 跳过注入和网络 Hook。 |
| 四种 Codex 引擎/辅助进程 | 按默认 `target_processes` 启用网络与传播 Hook。 |
| 其它进程 | 仅在配置中按完整 exe 基名显式列出时才注入；不支持子串或空名单表示全部。 |

`powershell.exe`、`pwsh.exe`、`cmd.exe`、`git.exe`、`node.exe`、`python.exe` 等用户工具默认不注入。`child_injection_mode=inherit` 被拒绝。原调用的 `CREATE_SUSPENDED` 会保留，ANSI/Unicode 创建路径均受支持。

两个垫片都通过 PE 静态导入引用 `CodexProxy_Bootstrap()`；该函数不等待、不加载其它 DLL。`tdh.dll` 的 27 个类型正确的导出懒加载绝对系统目录中的 TDH，`version.dll` 转发 17 个版本 API。核心初始化在 DllMain 返回后的工作线程执行。安装事务失败会撤回整组 Hook。核心被固定在进程内，保证 Hook 和未完成 I/O 在进程退出前始终有效，不支持运行中热卸载。

注入器在 Loader Lock 外等待 `Local\CodexProxy_Ready_<pid>`，确认 `Local\CodexProxy_Hooks_<pid>` 所有权后才返回；调用方随后恢复主线程。PID 互斥量阻止侧载与另一份注入副本重复安装 Hook。直接侧载采用后台初始化，因此不能把“DLL 已加载”当成“网络 Hook 已就绪”；对必须保证首个请求已受控的启动路径，应使用挂起注入并等待就绪的启动器。`CodexProxy_WaitReady(ms)` 供 Loader Lock 外诊断：0=尚未就绪/超时，1=本副本生效，2=旁路/重复副本，3=初始化失败。

## 配置

复制 `config.example.json` 为 `config.json`，修改代理地址。查找顺序严格为：

1. `CODEX_PROXY_CONFIG` 指定且存在的文件；
2. 核心 DLL 同目录的 `config.json`；
3. `%LOCALAPPDATA%\codex-proxy\config.json`。

不读取当前工作目录中的配置。若选中的文件无效，不继续尝试低优先级配置，也不安装 Hook。解析是事务性的，拒绝非法端口、CIDR、枚举和字段类型。`proxy.port=0` 关闭重定向、FakeIP 和 WinHTTP 屏蔽。凭据为本地配置中的明文，日志不记录密码或网络载荷。

- `proxy.type`：`socks5` / `http`；HTTP 使用 CONNECT + 可选 Basic，SOCKS5 支持 RFC 1929 用户密码认证。HTTP 代理链路本身不使用 TLS。
- `proxy.ignore_system_proxy` 默认 true。仅在网络 Hook 生效且代理端口大于 0 时，清空 `WinHttpGetIEProxyConfigForCurrentUser` 输出，并使 `WinHttpGetProxyForUrl` 返回 `ERROR_WINHTTP_AUTODETECTION_FAILED`。关闭该字段时两项 API 保持原样。
- `fake_ip`：默认 `198.18.0.0/15`，支持 `/15` 到 `/30`，跳过首尾地址，以环形游标复用。按配置路径隔离的共享映射在进程间统一分配，复用前验证缓存，不使用每进程相互冲突的独立游标。池回绕后历史地址会改变含义，因此长时间缓存的旧地址仍有环形池固有的过期风险。
- `timeout`：支持 `connect_ms/send_ms/recv_ms`，也接受 `connect/send/recv`，范围 1..300000 毫秒。代理握手使用有期限的 I/O；不把握手临时 socket 超时遗留给应用。本地连接在这些设置之前旁路。
- `rules.allowed_ports`：默认 80/443，空数组表示全部端口；白名单外直连。`dns_mode` 控制目标端口 53，`proxy` 时允许该端口进入代理。它不表示禁用 FakeIP；域名解析与原始 DNS 数据包是两个不同入口。
- `ipv6_mode`：`proxy/direct/block`；v4-mapped IPv6 按 IPv4 处理。IPv6 socket 在 bind 前允许双栈，以连接 IPv4 代理。
- `udp_mode`：`auto/proxy/direct/block`。auto 在 SOCKS5 下使用 UDP Associate，HTTP 下按 `udp_fallback=block/direct` 处理。默认失败阻断；UDP Associate 失败后退避 60 秒。SOCKS5 UDP 分片被拒绝。
- `routing`：地址/域名条件之间为 OR，与端口和协议条件为 AND；无地址条件可用于纯端口/协议规则。支持 `ip_cidrs_v4`、`ip_cidrs_v6`、`domains`、`ports`、`protocols`。域名支持 `*`、`?` 和 `.example.com` 后缀。`priority_mode=order` 按顺序，`number` 按 priority 降序稳定排列。默认私网直连适用于 TCP 和 UDP；关闭 `use_default_private` 后可自行分流。
- `child_injection` 可为布尔值或 `{ "enabled": true, "exclude": [] }`。排除项按完整进程基名匹配。
- `logging.enabled/level` 控制文件日志；`traffic_monitor.enabled` 只记录方向、socket 和字节数，不记录载荷。兼容 `proxy_rules`、`traffic_logging`、`log_level` 等原配置字段。

回环地址 `127.0.0.0/8`、`::1`、v4-mapped loopback、localhost 以及分配给本机网卡的地址严格旁路，不能被路由规则改为代理。OAuth 1455/1457、本地 MCP、IPC 因此不需要端口特例。命中本地连接后，收发、WSAIoctl、完成查询、shutdown 和 closesocket 继续使用原生语义。

日志按本机日期追加到 `<dll_dir>\logs\proxy-YYYYMMDD.log`，不可写时依次尝试 `%LOCALAPPDATA%\codex-proxy\logs`、`%TEMP%\codex-proxy-logs`。跨进程写入串行化；从不向 stdout/stderr 写日志，避免破坏 Codex app-server/MCP 协议。

## 异步与验证边界

`GetAddrInfoExW` 只替换需要代理的域名为稳定存储的数值 FakeIP，所有 namespace/provider、hints、timeout、OVERLAPPED、callback、取消句柄均交给 Windows。返回结构仍由原生分配，使用 `FreeAddrInfoExW` 释放；同步完成和异步完成遵循 [Microsoft GetAddrInfoExW 契约](https://learn.microsoft.com/en-us/windows/win32/api/ws2tcpip/nf-ws2tcpip-getaddrinfoexw)。不手工伪造完成或调用用户 DNS callback。

ConnectEx 在提交 I/O 前登记上下文，并使同步返回与 IOCP 消费者共享一次握手结果。握手失败通过完成状态返回；不会作为成功隧道交给上层。UDP 复制 WSABUF 描述符，保留内核正在使用的封装缓冲区，取消完成被观察到后才释放；立即完成时也不手动重复调用用户 completion routine。未被应用观察的取消操作可能保留上下文直到进程退出。

CTest 包括纯配置/策略测试、真实 DLL 安装、静态 TDH 导入、异步 DNS、日志回退与 stdout 检查、挂起子进程传播、重复副本保护，以及本地模拟 SOCKS5/HTTP、ConnectEx/IOCP、UDP event/callback 收发。它们不需要 OpenAI 登录或外网服务。当前未对用户正在运行的 Store 桌面版、真实 OAuth 登录或真实上游代理做端到端验收；该验收应在启动器阶段完成。此阶段不会改变正在运行的 Codex 进程。

## 版权

- antigravity-proxy：Copyright (c) yuaotian and antigravity-proxy contributors，BSD-2-Clause；本项目的路由、协议、Hook、注入和版本转发基础来自该项目。
- MinHook：Copyright (C) 2009-2017 Tsuda Kageyu，BSD-2-Clause；原作者及贡献者列于 `AUTHORS.txt`。
- Hacker Disassembler Engine：Copyright (c) 2008-2009 Vyacheslav Patkov；原许可保留于 `LICENSE.txt`。
- nlohmann/json：Niels Lohmann and contributors，MIT；版权标记保留在 `include/nlohmann/json.hpp` 中，完整许可见 `LICENSE.txt`。

分发二进制时须一并分发 `LICENSE.txt`、`AUTHORS.txt` 和本 README。Codex-Proxy 不是 OpenAI 官方产品。
