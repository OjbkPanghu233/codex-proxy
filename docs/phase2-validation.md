# Phase 2 交付与验收

范围：保留 Phase 1 核心、测试和历史交付，新增启动器、宿主网络开关、安装与体检、离线配置编辑器和便携发布包。

## 构建与运行环境

- Windows x64，普通用户 token；MSVC 19.40.33811，CMake 3.28.3-msvc11，Ninja，Windows SDK 10.0.22621.0。
- C++17、`/utf-8`、Release `/MT`。MSIX 目录与全局系统代理未修改。
- Windows PowerShell 5.1.26100.9818、PowerShell 7.6.5 均运行一键构建、CTest 和打包流程。
- 中文 MSVC 的 `/showIncludes` 输出前缀按实际 `/utf-8` 编译参数探测，Ninja 已记录头文件依赖；CLI 包装器对象记录 248 条依赖，避免增量构建漏掉头文件改动。
- 完整构建 54 个步骤成功，0 编译错误。保留的上游 MinHook/HDE 在 `/W4` 下仍有编译警告；新增代码没有依靠禁用编译错误完成构建。

执行命令：

```powershell
.\build.ps1 -Config Release -Clean -RunTests -Package
.\build.ps1 -Config Release -RunTests -Package
```

CTest **43/43 通过，100%，0 失败**。PowerShell AST 校验覆盖全部 5 个项目脚本。原始记录在 `build-phase2-Release/configure.log`、`build.log`、`ctest.log`、`Testing/Temporary/LastTest.log`；发布包附带构建/测试日志。

## 验证矩阵

| 验证 | 结果与边界 |
| --- | --- |
| Phase 1 回归 | 原配置、CIDR、进程分类、FakeIP、认证、UDP、日志、TDH、DNS、WinHTTP、注入、IOCP 测试保留并通过 |
| 宿主网络 | JSON 缺省为 true；true/false 均有单元测试与真实 ChatGPT.exe 命名测试宿主加载验证；renderer 仍跳过 |
| CLI 纯逻辑 | exe 优先级、完整参数解析、PID 边界、Windows 引号/反斜杠/空参数/Unicode 往返 |
| Desktop 纯逻辑 | 路径优先级、WindowsApps 判断、已有实例动作选择、配置保护与同步判断 |
| 启动器真实转发 | --exec 挂起创建、Job、加载核心、等待就绪、恢复，分别通过模拟 SOCKS5 / HTTP Basic CONNECT 收发 |
| stdio / 退出码 | JSON 输出逐字节相同；stdin/stdout 二进制管道含 NUL 字节透传；stderr 无包装器额外输出，退出码 37 原样返回 |
| 热注入 | 对测试进程 --attach，在进程启动后传递配置并等待就绪；没有对真实桌面应用热注入 |
| 失败关闭 | 无效配置返回 125，不输出 stdout，不运行未受保护的新目标 |
| Job 清理 | 结束测试包装器后，测试目标和仍在 Job 中的孙进程被回收 |
| Desktop dry-run | Win32 子系统程序只读扫描，不弹框、不拉起目标、不注入；实际桌面进程 PID/启动时间快照前后相同 |
| 安装生命周期 | 临时目录部署真实发布文件、探测模拟 SOCKS5、创建两份快捷方式、Repair 保留配置、Check 文件哈希不变、Uninstall 恢复原第三方 TDH、Purge 清除受管目录 |
| PowerShell 跨版本 | 5.1 和 7.6 实跑；修复 pwsh → Python → Windows PowerShell 链路中 Get-FileHash 自动加载差异，文件校验使用 .NET SHA256 |
| 配置页面 | 独立无头 Chrome，桌面/375px 移动视图；中英切换、开关、规则编辑、导出下载、认证值预览隐藏、未知字段往返、非法输入、导入原型键拒绝；页面外部请求为 0 |
| PE 检查 | 桌面启动器为 Windows GUI 子系统；CLI 为控制台程序；包装器无动态 MSVC/UCRT 依赖；核心和两个垫片继续使用静态运行库 |

浏览器截图：`build-phase2-Release/evidence/config-web-desktop.png`、`config-web-mobile.png`。真实窗口只读检查与 dry-run 证据保留在同目录；不会把用户进程快照嵌入可分享发布包。

没有执行真实桌面的 --restart、--attach、可选目录同步，或真实用户目录的安装/卸载；没有进行 OpenAI 登录和可选外网接口测试。MSIX 别名实际启动、应用单实例参数转交和真实 OAuth 回调仍需由用户在独立应用会话中验收。热注入只接管新连接，旧连接不迁移。

## 创建与修改的文件

新增：

```text
build.ps1
config-web.html
src/core/LaunchRequest.hpp
src/launcher/CliLauncherLogic.hpp
src/launcher/DesktopLauncherLogic.hpp
src/launcher/LauncherSupport.hpp
src/launcher/CodexCliLauncher.cpp
src/launcher/CodexDesktopLauncher.cpp
scripts/ProxyTools.ps1
scripts/doctor.ps1
scripts/doctor.bat
scripts/install-windows.ps1
scripts/setup.bat
tools/package.py
tests/test_launcher_logic.cpp
tests/test_launcher_child.cpp
tests/test_launcher_e2e.cpp
tests/test_powershell_syntax.ps1
tests/test_installer.py
tests/test_config_web.py
docs/README-phase1.md
docs/phase2-validation.md
```

修改：

```text
CMakeLists.txt
README.md
config.example.json
src/core/Config.hpp
src/hooks/ProcessName.hpp
src/main.cpp
tools/build.py
tests/test_config.cpp
tests/test_process_name.cpp
tests/test_hooks.cpp
```

共新增 22 个文件、修改 10 个文件。版权文件和只读参考仓库保持原样；新代码的参考归属写入 README/源码注释。Phase 1 ZIP、`output/phase1` 与历史验证记录继续保留。

## 发布包

```text
output/codex-proxy-win-x64/
  codex-proxy.exe
  CodexDesktopLauncher.exe
  codex_proxy.dll
  version.dll
  tdh.dll
  config.example.json
  config-web.html
  README.md / LICENSE.txt / AUTHORS.txt / UPSTREAM.txt
  manifest.json / SHA256SUMS.txt
  scripts/ / docs/ / validation/
output/codex-proxy-win-x64.zip
output/SHA256SUMS.txt
```

发布根目录带 `.codex-proxy-package` 归属标记，打包器不会递归覆盖没有标记的输出目录。包内和外部 SHA-256 清单分别使用各自根目录的相对路径；最终逐项校验文件及 ZIP 哈希，并检查 ZIP 路径没有绝对路径或上级跳转。
