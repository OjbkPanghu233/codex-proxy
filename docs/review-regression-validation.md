# Phase 2 独立审查修复与回归验收

本次修复保留 Phase 1 / Phase 2 原有测试，在原有 43 项 CTest 上新增 7 项，并扩展配置与安装生命周期测试，共 50 项。

| 审查项 | 修复 | 回归测试 |
| --- | --- | --- |
| P1：域名 direct 身份丢失 | 所有符合 FakeIP 条件的域名均保留映射；连接时匹配域名 direct 后，通过原始 DNS provider 解析真实地址 | `review_dns_direct`：公网地址、仅域名 direct、默认 proxy、IPv4 / mapped IPv6，确认最终调用真实目标直连；localhost 继续旁路 |
| P1：ConnectEx OVERLAPPED 复用 | 五种异步入口统一失效已完成 ConnectEx 状态；共享所有权保证观察者与互斥量生命周期，未完成状态保留 | `review_connect_reuse`：WSARecv / WSASend / WSARecvFrom / WSASendTo / ConnectEx 五入口，检查 999 字节旧记录不会覆盖新完成的 17 字节，旧所有权释放，pending 状态不提前删除 |
| P1：子进程丢失 attach 配置 | 注入前创建子 PID LaunchRequest，写入父进程实际 loadedPath；持有映射直到子进程 Ready，随后恢复主线程 | `hooks_child_config_request`：父进程仅用 PID 请求加载自定义 /29 配置；继承环境故意指向禁用代理的另一份配置；ANSI / Wide 子进程与孙进程仍使用自定义 FakeIP 配置，包含 CREATE_SUSPENDED |
| P1：自定义安装目录的 CLI 配置 | 增加 UTF-8 受管定位文件；查找顺序 env → 同目录 JSON → 定位文件 → LOCALAPPDATA；卸载按清单哈希清理 / 恢复 | `test_config`：完整优先级、Unicode / BOM / CRLF、丢失与相对路径回退；`installer_lifecycle`：非默认 Destination、真实静态 TDH 导入的 codex.exe、隔离 LOCALAPPDATA、无 env 配置、卸载移除定位文件 |
| P2：UDP 完成后占用缓冲区 | 完成即从活动接收表移除；swap 释放 payload / WSABUF vector 容量；仅保留无缓冲区指针的轻量完成结果供后续通知使用，IOCP / APC 消费、复用与关闭时清理 | `review_udp_release`：256 个独立操作各预留 1 MiB，检查 weak_ptr 到期、活动表为空、capacity 为 0、后续完成结果可用；取消完成前仍保留 provider 缓冲区 |
| P2：sendto 隐式 connect UDP | 未连接 socket 只建立 Associate，使用显式 relay 地址发送，不设置逻辑默认目标；本地单个数据报不改变整个 socket 策略，接收按来源区分 relay / 直连 | `review_udp_unconnected`：真实 UDP sockets，sendto / 同步 WSASendTo / overlapped WSASendTo；getpeername 始终 WSAENOTCONN，同时接收代理与本地回包 |
| P2：立即完成 UDP 错误丢失 | WSARecv / WSARecvFrom 立即完成路径读取解码错误，设置 LastError 并返回 SOCKET_ERROR，保留已复制长度与后续通知翻译 | `review_udp_immediate`：两个入口分别验证 WSAEMSGSIZE、畸形封装 WSAECONNRESET，检查 payload / bytes / 缓存错误与缓冲区释放 |
| P2：ByName 本机地址未旁路 | ANSI / Wide 解析完成后，在 PerformProxyConnect 前应用 IsLocalSockaddr，清理旧目标状态并更新本地旁路标志 | `review_byname_local`：枚举本机非回环网卡 IPv4 / IPv6，配置显式全网代理，确认直接连接本机地址且不进入代理超时设置路径；已有 hooks_local 继续验证 localhost |

纯 Hook 回归程序直接编译实际 Hooks.cpp，替换受控 provider 函数指针进行断言，不安装系统 Hook。UDP socket 验证只收发测试创建的本地端口；子进程树与 TDH 加载只使用隔离测试二进制。没有对当前运行的 ChatGPT.exe 执行注入、重启或配置变更。

实现遵循微软 [WSARecvFrom](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsarecvfrom) 与 [WSASendTo](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasendto) 的立即完成、异步通知与错误返回约定。已经完成的轻量翻译记录不持有用户缓冲区；未完成取消请求的缓冲区仍需等待 provider 完成通知才释放。

验收命令：

```powershell
.\build.ps1 -Config Release -RunTests -Package
```

最终要求：0 编译错误，CTest 50/50 通过，PowerShell AST 5/5 通过，便携目录、ZIP、内部与外部 SHA256SUMS 同步生成。原始结果保存在 `build-phase2-Release/build.log`、`ctest.log` 与 `Testing/Temporary/LastTest.log`，发布包附带对应构建 / CTest 日志。
