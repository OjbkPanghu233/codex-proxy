# Phase 1 交付与验证记录

验证日期：2026-11-25，Windows x64，普通用户进程。

- MSVC：19.40.33811.0，工具集目录 `D:\VisualStudioIDE\VC\Tools\MSVC\14.40.33807`。
- CMake：Visual Studio 自带 3.28，Ninja，Release，C++17，`/utf-8`、`/MT`。
- Windows SDK：10.0.22621.0。系统注册表原 SDK 路径已失效；从本机缓存的微软安装包执行管理映像解压到项目 `.deps/winsdk`，没有修复或修改全局 SDK 注册表。
- 命令：`python tools/build.py --build-dir build-verify`。
- 首次完整构建 44 个步骤成功；最终增量构建成功，0 编译错误。上游原样保留的 MinHook/HDE 在 `/W4` 下有编译警告，不影响测试结果。
- CTest：**31/31 通过，0 失败**，最后一次总用时 **2.52 秒**。
- 分发目录：`output/phase1/bin` 与 `output/phase1/lib`。

原始记录保留在 `build-verify/configure.log`、`build-verify/build.log`、`build-verify/ctest.log` 和 `build-verify/Testing/Temporary/LastTest.log`。交付目录另附 CTest 输出和 SHA-256 清单。

## 已验证行为

| 类别 | 验证内容 |
| --- | --- |
| 配置 | 默认进程族、ignore_system_proxy、事务解析、非法字段/端口/枚举/CIDR、环境变量优先级、Unicode 路径、显式空目标列表不放行任何进程 |
| 路由 | IPv4/IPv6 CIDR、畸形地址拒绝、通配域名、大小写与末尾点、纯端口规则、协议规则、数字优先级、默认私网直连 |
| 本地目标 | IPv4/IPv6/v4-mapped loopback、localhost、地址长度、真实网卡本机地址；真实本地 TCP 与 WSAConnectByName 原生输出 |
| FakeIP | 环形回绕、旧缓存验证、大小写规范化、跨进程统一游标与反查 |
| 认证与传输 | RFC 4648 Base64 向量、真实 SOCKS5 用户密码字节流、错误认证版本拒绝、HTTP Basic CONNECT、IPv6 authority、保留隧道首包、阻塞 socket 接收期限 |
| UDP | 策略与退避、封装/解封装、拒绝分片、域名形式的 relay、IOCP/GQCSEx、event/WSAGetOverlappedResult、延后与立即完成 callback、WSABUF 描述符生命周期 |
| Hook | 真实 DLL 加载并安装；同步 DNS、GetAddrInfoW/gethostbyname、GetAddrInfoExW 同步/event/callback、原生释放、本地 DNS 旁路 |
| WinHTTP | 屏蔽时输出清零与指定错误；ignore_system_proxy=false、port=0、桌面主进程时 API 入口保持原样 |
| 进程 | Chromium 命令行分类、桌面主进程仅传播、renderer 跳过、挂起子进程注入、保留调用者的 CREATE_SUSPENDED、用户工具不注入、不同路径 DLL 单实例保护 |
| IOCP | ConnectEx 首包、一次握手结果、再次查询完成字节数、握手失败在 GQCS/GQCSEx 中报告失败 |
| 垫片 | tdh.dll 真实转发与系统返回值比较；名为 codex.exe 的测试程序通过 PE 静态导入启动；version.dll 真实读取系统 kernel32.dll 版本资源 |
| 日志 | 多线程写入、LOCALAPPDATA 与 TEMP 两级不可写回退；捕获 stdout/stderr 为 **0 字节** |

## 二进制检查

`dumpbin` 确认：

- `codex_proxy.dll` 导出 `CodexProxy_Bootstrap`、`CodexProxy_WaitReady`；依赖仅 WS2_32、IPHLPAPI、KERNEL32，无动态 MSVC/UCRT 依赖。
- `tdh.dll` 的静态依赖包含 `codex_proxy.dll`；导出 27 个类型正确的 TDH API。
- `version.dll` 转发 17 个系统版本 API，并静态依赖核心 DLL。

## 设计与验收边界

MSIX WindowsApps 保持只读，核心不写入应用包；本阶段没有交付桌面/CLI 启动器。挂起注入器等待核心就绪再返回。直接侧载的工作线程存在初始化时间窗，不能把 PE 加载成功等同于 Hook 已就绪；后续启动器应遵守就绪握手。

本阶段使用隔离测试程序和本机模拟代理验证，没有注入当前 Codex 会话、改变系统代理、登录 OpenAI 或操作实际 Store 桌面版。真实桌面应用、OAuth 1455/1457 回调和实际上游网络的端到端验收留到启动器阶段。网络 Hook 范围按本次 Codex 需求实施；它与参考仓库文档建议的 Antigravity 全宿主网络 Hook 策略有所区别，不能互相替代物理验收。

参考源码版本记录在 `UPSTREAM.txt`；MinHook、HDE、antigravity-proxy 的 BSD 归属和 nlohmann/json 的 MIT 许可保留于 `LICENSE.txt`、`AUTHORS.txt`、`README.md`。

## 创建与修改的文件

`LICENSE.txt`、`AUTHORS.txt` 为预置文件的增补；以下清单中的其余文件为本阶段新建或从参考仓库移植后适配。预置的 MinHook/HDE 源码与两个 include 头文件保持原样。

```text
.gitignore
CMakeLists.txt
LICENSE.txt
AUTHORS.txt
README.md
UPSTREAM.txt
config.example.json
src/main.cpp
tools/build.py
docs/phase1-validation.md
src/core/Config.hpp
src/core/DllIdentity.hpp
src/core/Logger.hpp
src/core/Paths.hpp
src/core/UdpPolicy.hpp
src/network/FakeIP.hpp
src/network/HttpConnect.hpp
src/network/LocalTargetPolicy.hpp
src/network/SocketFamily.hpp
src/network/SocketIo.hpp
src/network/SocketWrapper.hpp
src/network/Socks5.hpp
src/network/Socks5Udp.hpp
src/network/TrafficMonitor.hpp
src/network/UdpAssociateBackoff.hpp
src/hooks/DnsPolicy.hpp
src/hooks/Hooks.cpp
src/hooks/Hooks.hpp
src/hooks/ProcessName.hpp
src/injection/ProcessInjector.hpp
src/proxy/ShimEntry.cpp
src/proxy/tdh.def
src/proxy/TdhShim.cpp
src/proxy/version.def
src/proxy/VersionProxy.cpp
tests/Test.hpp
tests/test_config.cpp
tests/test_fake_ip.cpp
tests/test_hooks.cpp
tests/test_ipv6_parser.cpp
tests/test_local_target_policy.cpp
tests/test_logger.cpp
tests/test_native_tdh.cpp
tests/test_process_name.cpp
tests/test_protocols.cpp
tests/test_proxy_auth.cpp
tests/test_routing.cpp
tests/test_socket_family.cpp
tests/test_tdh_shim.cpp
tests/test_udp_associate_backoff.cpp
tests/test_udp_policy.cpp
```

Total: 51 source/documentation files.
