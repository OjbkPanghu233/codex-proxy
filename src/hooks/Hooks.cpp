// Derived from antigravity-proxy (BSD-2-Clause); see LICENSE.txt / AUTHORS.txt.
// 防止 windows.h 自动包含 winsock.h (避免与 winsock2.h 冲突)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <MinHook.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <mswsock.h>
#include <winhttp.h>
#include "Hooks.hpp"
#include "DnsPolicy.hpp"
#include <algorithm>
#include <charconv>
#include <cctype>
#include <fstream>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <shared_mutex>
#include <atomic>
#include <memory>
#include <utility>
#include "../core/Config.hpp"
#include "../core/LaunchRequest.hpp"
#include "../core/Logger.hpp"
#include "../network/SocketWrapper.hpp"
#include "../network/FakeIP.hpp"
#include "../network/Socks5.hpp"
#include "../network/Socks5Udp.hpp"
#include "../network/UdpAssociateBackoff.hpp"
#include "../network/HttpConnect.hpp"
#include "../network/SocketIo.hpp"
#include "../network/SocketFamily.hpp"
#include "../network/LocalTargetPolicy.hpp"
#include "../network/TrafficMonitor.hpp"
#include "../injection/ProcessInjector.hpp"
#include "ProcessName.hpp"

using Hooks::GetCreateProcessTargetBaseNameA;
using Hooks::ToLowerAsciiCopy;

// ============= 函数指针类型定义 =============
typedef int (WSAAPI *connect_t)(SOCKET, const struct sockaddr*, int);
typedef SOCKET (WSAAPI *socket_t)(int, int, int);
typedef SOCKET (WSAAPI *WSASocketA_t)(int, int, int, LPWSAPROTOCOL_INFOA, GROUP, DWORD);
typedef SOCKET (WSAAPI *WSASocketW_t)(int, int, int, LPWSAPROTOCOL_INFOW, GROUP, DWORD);
typedef int (WSAAPI *WSAConnect_t)(SOCKET, const struct sockaddr*, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS);
typedef struct hostent* (WSAAPI *gethostbyname_t)(const char* name);
typedef int (WSAAPI *getaddrinfo_t)(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);
typedef int (WSAAPI *getaddrinfoW_t)(PCWSTR, PCWSTR, const ADDRINFOW*, PADDRINFOW*);
typedef int (WSAAPI *send_t)(SOCKET, const char*, int, int);
typedef int (WSAAPI *recv_t)(SOCKET, char*, int, int);
typedef int (WSAAPI *sendto_t)(SOCKET, const char*, int, int, const struct sockaddr*, int);
typedef int (WSAAPI *recvfrom_t)(SOCKET, char*, int, int, struct sockaddr*, int*);
typedef int (WSAAPI *closesocket_t)(SOCKET);
typedef int (WSAAPI *shutdown_t)(SOCKET, int);
typedef int (WSAAPI *WSASend_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI *WSARecv_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI *WSASendTo_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, const struct sockaddr*, int, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI *WSARecvFrom_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, struct sockaddr*, LPINT, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef BOOL (WSAAPI *WSAConnectByNameA_t)(SOCKET, LPCSTR, LPCSTR, LPDWORD, LPSOCKADDR, LPDWORD, LPSOCKADDR, const struct timeval*, LPWSAOVERLAPPED);
typedef BOOL (WSAAPI *WSAConnectByNameW_t)(SOCKET, LPWSTR, LPWSTR, LPDWORD, LPSOCKADDR, LPDWORD, LPSOCKADDR, const struct timeval*, LPWSAOVERLAPPED);
typedef int (WSAAPI *WSAIoctl_t)(SOCKET, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef BOOL (WSAAPI *WSAGetOverlappedResult_t)(SOCKET, LPWSAOVERLAPPED, LPDWORD, BOOL, LPDWORD);
typedef BOOL (WINAPI *GetQueuedCompletionStatus_t)(HANDLE, LPDWORD, PULONG_PTR, LPOVERLAPPED*, DWORD);
typedef BOOL (WINAPI *CreateProcessW_t)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *CreateProcessA_t)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
// GetQueuedCompletionStatusEx 函数指针类型 - 用于批量获取 IOCP 事件（现代高性能应用必需）
typedef BOOL (WINAPI *GetQueuedCompletionStatusEx_t)(
    HANDLE CompletionPort,
    LPOVERLAPPED_ENTRY lpCompletionPortEntries,
    ULONG ulCount,
    PULONG ulNumEntriesRemoved,
    DWORD dwMilliseconds,
    BOOL fAlertable
);

// ============= 原始函数指针 =============
decltype(&GetAddrInfoExW) fpGetAddrInfoExW = nullptr;
decltype(&WinHttpGetIEProxyConfigForCurrentUser) fpWinHttpIEProxy = nullptr;
decltype(&WinHttpGetProxyForUrl) fpWinHttpProxyForUrl = nullptr;
decltype(&ioctlsocket) fpIoctlSocket=nullptr;
decltype(&WSAEventSelect) fpWSAEventSelect=nullptr;
decltype(&WSAAsyncSelect) fpWSAAsyncSelect=nullptr;
connect_t fpConnect = NULL;
socket_t fpSocket = NULL;
WSASocketA_t fpWSASocketA = NULL;
WSASocketW_t fpWSASocketW = NULL;
WSAConnect_t fpWSAConnect = NULL;
gethostbyname_t fpGetHostByName = NULL;
getaddrinfo_t fpGetAddrInfo = NULL;
getaddrinfoW_t fpGetAddrInfoW = NULL;
send_t fpSend = NULL;
recv_t fpRecv = NULL;
sendto_t fpSendTo = NULL;
recvfrom_t fpRecvFrom = NULL;
closesocket_t fpCloseSocket = NULL;
shutdown_t fpShutdown = NULL;
WSASend_t fpWSASend = NULL;
WSARecv_t fpWSARecv = NULL;
WSASendTo_t fpWSASendTo = NULL;
WSARecvFrom_t fpWSARecvFrom = NULL;
WSAConnectByNameA_t fpWSAConnectByNameA = NULL;
WSAConnectByNameW_t fpWSAConnectByNameW = NULL;
WSAIoctl_t fpWSAIoctl = NULL;
WSAGetOverlappedResult_t fpWSAGetOverlappedResult = NULL;
GetQueuedCompletionStatus_t fpGetQueuedCompletionStatus = NULL;
LPFN_CONNECTEX fpConnectEx = NULL;
CreateProcessW_t fpCreateProcessW = NULL;
CreateProcessA_t fpCreateProcessA = NULL;
GetQueuedCompletionStatusEx_t fpGetQueuedCompletionStatusEx = NULL; // 批量 IOCP 事件获取

// ============= 辅助函数 =============

// 保存原始目标地址用于 SOCKS5 握手
struct OriginalTarget {
    std::string host;
    uint16_t port;
};

// 线程本地存储，保存当前连接的原始目标
thread_local OriginalTarget g_currentTarget;

// 记录“socket -> 原始目标”的映射，用于在 closesocket/shutdown 时输出更可复盘的断开日志
// 设计意图：满足“连接断开过程”日志需求，同时避免在 close 时重复做高成本解析。
struct SocketTargetInfo {
    std::string host;
    uint16_t port = 0;
    ULONGLONG establishedTick = 0;
};
static std::unordered_map<SOCKET, SocketTargetInfo> g_socketTargets;
static std::mutex g_socketTargetsMtx;

// 回环连接一旦命中早期旁路，后续收发与关闭阶段也必须保持原始 WinSock 语义。
static std::unordered_set<SOCKET> g_localBypassSockets;
static std::shared_mutex g_localBypassSocketsMtx;

static void SetLocalBypassSocket(SOCKET s, bool enabled) {
    if (s == INVALID_SOCKET) return;
    std::unique_lock<std::shared_mutex> lock(g_localBypassSocketsMtx);
    if (enabled) {
        g_localBypassSockets.insert(s);
    } else {
        g_localBypassSockets.erase(s);
    }
}

static bool IsLocalBypassSocket(SOCKET s) {
    if (s == INVALID_SOCKET) return false;
    std::shared_lock<std::shared_mutex> lock(g_localBypassSocketsMtx);
    return g_localBypassSockets.find(s) != g_localBypassSockets.end();
}

static bool IsPendingConnectError(int error) {
    return error == WSAEWOULDBLOCK || error == WSAEINPROGRESS ||
           error == WSAEALREADY || error == WSA_IO_PENDING;
}

static void UpdateLocalBypassSocketAfterConnect(SOCKET s, bool succeeded, int error) {
    SetLocalBypassSocket(s, succeeded || IsPendingConnectError(error));
}

static void RememberSocketTarget(SOCKET s, const std::string& host, uint16_t port) {
    if (s == INVALID_SOCKET || host.empty() || port == 0) return;
    std::lock_guard<std::mutex> lock(g_socketTargetsMtx);
    g_socketTargets[s] = SocketTargetInfo{host, port, GetTickCount64()};
}

static bool TryGetSocketTarget(SOCKET s, SocketTargetInfo* out) {
    if (!out || s == INVALID_SOCKET) return false;
    std::lock_guard<std::mutex> lock(g_socketTargetsMtx);
    auto it = g_socketTargets.find(s);
    if (it == g_socketTargets.end()) return false;
    *out = it->second;
    return true;
}

static void ForgetSocketTarget(SOCKET s) {
    if (s == INVALID_SOCKET) return;
    std::lock_guard<std::mutex> lock(g_socketTargetsMtx);
    g_socketTargets.erase(s);
}

// ConnectEx 异步上下文
struct ConnectCompletion {
    std::mutex mutex;
    bool done = false, success = false;
    DWORD bytes = 0;
    int error = 0;
};
struct ConnectExContext {
    std::shared_ptr<ConnectCompletion> completion = std::make_shared<ConnectCompletion>();
    SOCKET sock;
    std::string host;
    uint16_t port;
    const char* sendBuf;
    DWORD sendLen;
    bool isUdp = false;      // 是否为 UDP ConnectEx（用于 QUIC/HTTP3 的透明代理）
    ULONGLONG createdTick; // 记录创建时间，便于清理超时上下文
};

static std::unordered_map<LPOVERLAPPED, ConnectExContext> g_connectExPending;
static std::mutex g_connectExMtx;
static std::mutex g_connectExHookMtx;
// ConnectEx 在不同 Provider 下可能返回不同函数指针，这里按 CatalogEntryId 记录各自的 trampoline
static std::unordered_map<DWORD, LPFN_CONNECTEX> g_connectExOriginalByCatalog;
// ConnectEx 目标函数指针可能被多个 Provider 复用，这里按“目标函数地址”记录 trampoline，便于复用与补全 Catalog 映射
static std::unordered_map<void*, LPFN_CONNECTEX> g_connectExTrampolineByTarget;

// ============= UDP/QUIC 代理支持（SOCKS5 UDP Associate） =============

// UDP 代理上下文：每个 UDP socket 独立维护一个 UDP Associate（最简单、最可控）
// 设计意图：避免多 socket 复用同一 relay 导致的回包归属问题（KISS 优先）。
struct UdpProxyContext {
    SOCKET udpSock = INVALID_SOCKET;
    SOCKET controlSock = INVALID_SOCKET; // SOCKS5 UDP Associate 的 TCP 控制连接（需保持打开）
    sockaddr_storage relayAddr{};        // 代理返回的 UDP relay 地址
    int relayAddrLen = 0;
    bool relayConnected = false;         // udpSock 是否已 connect 到 relayAddr

    // 对于 connected UDP socket (send/recv)，需要记住“逻辑上的目标”，用于封装 SOCKS5 UDP 头
    std::string defaultTargetHost;
    uint16_t defaultTargetPort = 0;
    bool hasDefaultTarget = false;

    ULONGLONG createdTick = 0;
};
static std::unordered_map<SOCKET, UdpProxyContext> g_udpProxy;
static std::mutex g_udpProxyMtx;

// UDP Overlapped 上下文（用于 IOCP/CompletionRoutine 场景下解封装/调整 bytesTransferred）
struct UdpOverlappedSendCtx {
    std::mutex completionMutex;
    bool completed = false;
    DWORD completedBytes = 0;
    SOCKET sock = INVALID_SOCKET;
    std::vector<WSABUF> bufs;            // [0]=header, [1..]=用户 payload（仅复制描述符，不复制数据）
    std::vector<uint8_t> header;         // SOCKS5 UDP 头（需保持到完成）
    DWORD userBytes = 0;                 // 用户视角 payload bytes（不含 header）
    LPDWORD userBytesPtr = nullptr;      // 指向用户 lpNumberOfBytesSent（可为空）
    LPWSAOVERLAPPED_COMPLETION_ROUTINE userCompletion = nullptr;
};

struct UdpOverlappedRecvCtx {
    int completionError=0;
    std::mutex completionMutex;
    bool completed = false;
    DWORD completedBytes = 0;
    std::vector<WSABUF> userBuffers;
    SOCKET sock = INVALID_SOCKET;
    std::vector<uint8_t> recvBuf;        // 实际接收缓冲区（包含 SOCKS5 UDP 头 + payload）
    LPWSABUF userBufs = nullptr;
    DWORD userBufCount = 0;
    LPDWORD userBytesPtr = nullptr;
    LPDWORD userFlagsPtr = nullptr;

    sockaddr* userFrom = nullptr;
    LPINT userFromLen = nullptr;
    sockaddr_storage fromTmp{};
    int fromTmpLen = (int)sizeof(fromTmp);

    LPWSAOVERLAPPED_COMPLETION_ROUTINE userCompletion = nullptr;
};

static std::unordered_map<LPWSAOVERLAPPED, std::shared_ptr<UdpOverlappedSendCtx>> g_udpOvlSend;
static std::unordered_map<LPWSAOVERLAPPED, std::shared_ptr<UdpOverlappedRecvCtx>> g_udpOvlRecv;
// Completed operations retain only the translation needed by a later IOCP/APC
// notification. They never retain payload allocations or user buffer pointers.
struct UdpCompletedResult {
    SOCKET sock = INVALID_SOCKET;
    DWORD bytes = 0;
    int error = 0;
    LPWSAOVERLAPPED_COMPLETION_ROUTINE callback = nullptr;
};
static std::unordered_map<LPWSAOVERLAPPED, UdpCompletedResult> g_udpCompleted;
static std::mutex g_udpOvlMtx;
static SOCKET ConnectTcpToProxyServer(const Core::ProxyConfig& proxy);

static std::once_flag g_runtimeConfigLogOnce;

static Core::UdpAction GetEffectiveUdpAction(const Core::Config& config) {
    return Core::ResolveUdpAction(
        config.rules.udp_mode,
        config.proxy.type,
        config.rules.udp_fallback);
}

static std::string GetUdpPolicyLabel(const Core::Config& config) {
    return "udp_mode=" + config.rules.udp_mode +
           ", effective=" + Core::UdpActionName(GetEffectiveUdpAction(config));
}


static std::mutex g_socketModesMutex;
static std::unordered_map<SOCKET,bool> g_socketNonblocking;
static void RememberSocketMode(SOCKET s,bool nonblocking) {
    if(s==INVALID_SOCKET) return;
    std::lock_guard<std::mutex> lock(g_socketModesMutex);
    g_socketNonblocking[s]=nonblocking;
}
int WSAAPI DetourIoctlSocket(SOCKET s,long command,u_long* argument) {
    int result=fpIoctlSocket(s,command,argument);
    if(result==0 && command==FIONBIO && argument) RememberSocketMode(s,*argument!=0);
    return result;
}
int WSAAPI DetourWSAEventSelect(SOCKET s,WSAEVENT event,long events) {
    int result=fpWSAEventSelect(s,event,events);
    if(result==0 && events) RememberSocketMode(s,true);
    return result;
}
int WSAAPI DetourWSAAsyncSelect(SOCKET s,HWND window,u_int message,long events) {
    int result=fpWSAAsyncSelect(s,window,message,events);
    if(result==0 && events) RememberSocketMode(s,true);
    return result;
}
// Bound even a blocking connect to timeout.connect_ms, preserving the caller's
// Winsock blocking/event-select mode. Pre-injection sockets of unknown mode are
// left unchanged; suspended startup avoids that case in launchers.
static int ConnectProxyWithDeadline(SOCKET s,const sockaddr* address,int length,bool wsa) {
    bool temporaryNonblocking=false;
    {
        std::lock_guard<std::mutex> lock(g_socketModesMutex);
        auto mode=g_socketNonblocking.find(s);
        temporaryNonblocking=mode!=g_socketNonblocking.end() && !mode->second;
    }
    if(temporaryNonblocking) { u_long mode=1; if(fpIoctlSocket(s,FIONBIO,&mode)!=0) return SOCKET_ERROR; }
    int result=wsa?fpWSAConnect(s,address,length,nullptr,nullptr,nullptr,nullptr):fpConnect(s,address,length);
    int error=result==SOCKET_ERROR?WSAGetLastError():0;
    if(result==SOCKET_ERROR && (error==WSAEWOULDBLOCK || error==WSAEINPROGRESS)) {
        result=Network::SocketIo::WaitConnect(s,Core::Config::Instance().timeout.connect_ms)?0:SOCKET_ERROR;
        error=result==SOCKET_ERROR?WSAGetLastError():0;
    }
    if(temporaryNonblocking) { u_long mode=0; fpIoctlSocket(s,FIONBIO,&mode); }
    if(result==SOCKET_ERROR) WSASetLastError(error);
    return result;
}

static void ConfigureCreatedSocketForProxy(SOCKET socket, int addressFamily, const char* api) {
    if (socket == INVALID_SOCKET || addressFamily != AF_INET6) return;
    auto& config = Core::Config::Instance();
    if (config.proxy.port == 0 || config.rules.ipv6_mode != "proxy") return;

    int error = 0;
    const Network::DualStackResult result =
        Network::EnsureIpv6DualStack(socket, addressFamily, &error);
    if (result == Network::DualStackResult::Failed) {
        Core::Logger::Warn(std::string(api) +
                           ": IPv6 socket 启用 dual-stack 失败, sock=" +
                           std::to_string((unsigned long long)socket) +
                           ", WSA错误码=" + std::to_string(error));
    } else if (result == Network::DualStackResult::Enabled &&
               Core::Logger::IsEnabled(Core::LogLevel::Debug)) {
        Core::Logger::Debug(std::string(api) +
                            ": 已为代理模式启用 IPv6 dual-stack, sock=" +
                            std::to_string((unsigned long long)socket));
    }
}

static bool PrepareIpv4MappedProxyDestination(SOCKET socket, const sockaddr_in6& destination) {
    if (!Network::IsIpv4MappedAddress(destination)) return true;

    int error = 0;
    const Network::DualStackResult result =
        Network::EnsureIpv6DualStack(socket, AF_INET6, &error);
    if (result != Network::DualStackResult::Failed) return true;

    const int finalError = error != 0 ? error : WSAEAFNOSUPPORT;
    Core::Logger::Error(
        "IPv6 socket 仍为 v6-only，不能连接 v4-mapped 代理端点；"
        "请确保 socket 在 bind 前允许 dual-stack, sock=" +
        std::to_string((unsigned long long)socket) +
        ", WSA错误码=" + std::to_string(finalError));
    WSASetLastError(finalError);
    return false;
}

static std::string WideToUtf8(PCWSTR input) {
    if (!input) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, input, -1, NULL, 0, NULL, NULL);
    if (len <= 0) return "";
    std::string result(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, input, -1, &result[0], len, NULL, NULL);
    if (!result.empty() && result.back() == '\0') result.pop_back();
    return result;
}

static std::string_view TrimView(std::string_view s) {
    while (!s.empty() && std::isspace((unsigned char)s.front())) s.remove_prefix(1);
    while (!s.empty() && std::isspace((unsigned char)s.back())) s.remove_suffix(1);
    return s;
}

// CRIT-3: DNS 阶段需要尽可能拿到端口，避免 direct+domains+ports 规则因 port=0 永远命不中而分配 FakeIP
static uint16_t ParseServiceNameToPortA(PCSTR pServiceName, const char* proto) {
    if (!pServiceName) return 0;
    std::string_view s = TrimView(std::string_view(pServiceName));
    if (s.empty()) return 0;

    // 1) 纯数字端口（最常见）
    uint32_t port = 0;
    auto rc = std::from_chars(s.data(), s.data() + s.size(), port, 10);
    if (rc.ec == std::errc() && rc.ptr == s.data() + s.size()) {
        if (port > 0 && port <= 65535) return (uint16_t)port;
        return 0;
    }

    // 2) 服务名（如 "https"），尝试系统 services 映射
    const std::string name(s);
    const char* protocol = (proto && *proto) ? proto : "tcp";
    servent* se = getservbyname(name.c_str(), protocol);
    if (!se) return 0;
    const int p = ntohs((u_short)se->s_port);
    if (p > 0 && p <= 65535) return (uint16_t)p;
    return 0;
}

static uint16_t ParseServiceNameToPortW(PCWSTR pServiceName, const char* proto) {
    if (!pServiceName) return 0;
    const std::string s = WideToUtf8(pServiceName);
    if (s.empty()) return 0;
    return ParseServiceNameToPortA(s.c_str(), proto);
}

// 获取 socket 类型（SOCK_STREAM / SOCK_DGRAM），用于避免误把 UDP/QUIC 当成 TCP 走代理
static bool TryGetSocketType(SOCKET s, int* outType) {
    if (!outType) return false;
    *outType = 0;
    int soType = 0;
    int optLen = sizeof(soType);
    if (getsockopt(s, SOL_SOCKET, SO_TYPE, (char*)&soType, &optLen) != 0) {
        return false;
    }
    *outType = soType;
    return true;
}

static std::string GetCreateProcessTargetBaseNameW(LPCWSTR applicationName, LPCWSTR commandLine) {
    const std::string app = WideToUtf8(applicationName);
    const std::string cmd = WideToUtf8(commandLine);
    return GetCreateProcessTargetBaseNameA(app.empty() ? nullptr : app.c_str(),
                                           cmd.empty() ? nullptr : cmd.c_str());
}

static void CloseSocketCompat(SOCKET s) {
    if (s != INVALID_SOCKET) { if (fpCloseSocket) fpCloseSocket(s); else closesocket(s); }
}

static int GetSocketTypeForProxyDecision(SOCKET s, bool* outKnown = nullptr) {
    int soType = 0;
    const bool known = TryGetSocketType(s, &soType);
    if (outKnown) *outKnown = known;
    return known ? soType : SOCK_STREAM;
}

// 获取当前 socket 的 Provider CatalogEntryId，用于在多 Provider 环境下正确调用对应的 ConnectEx trampoline
static bool TryGetSocketCatalogEntryId(SOCKET s, DWORD* outCatalogEntryId) {
    if (!outCatalogEntryId) return false;
    *outCatalogEntryId = 0;
    // 说明：WSAPROTOCOL_INFOA 的 dwCatalogEntryId 在新 SDK 下会触发弃用告警，改用 W 版本避免 C4996
    WSAPROTOCOL_INFOW info{};
    int optLen = sizeof(info);
    if (getsockopt(s, SOL_SOCKET, SO_PROTOCOL_INFOW, (char*)&info, &optLen) != 0) {
        return false;
    }
    *outCatalogEntryId = info.dwCatalogEntryId;
    return true;
}

static LPFN_CONNECTEX GetOriginalConnectExForSocket(SOCKET s) {
    static std::once_flag s_catalogMissingOnce;
    static std::once_flag s_mapMissingOnce;

    DWORD catalogId = 0;
    if (TryGetSocketCatalogEntryId(s, &catalogId)) {
        {
            std::lock_guard<std::mutex> lock(g_connectExHookMtx);
            auto it = g_connectExOriginalByCatalog.find(catalogId);
            if (it != g_connectExOriginalByCatalog.end() && it->second) {
                return it->second;
            }
        }
        if (fpConnectEx) {
            // 只记录一次，避免刷屏；用于定位“某些 Provider 的 ConnectEx 没被正确记录”的现场
            std::call_once(s_mapMissingOnce, [catalogId]() {
                Core::Logger::Warn("ConnectEx: 未找到 CatalogEntryId=" + std::to_string(catalogId) +
                                   " 的 trampoline 映射，使用兜底实现");
            });
        }
        return fpConnectEx;
    }
    // 兜底：兼容单 Provider 场景（或获取 Catalog 失败）
    if (fpConnectEx) {
        std::call_once(s_catalogMissingOnce, []() {
            Core::Logger::Warn("ConnectEx: 无法获取 socket 的 CatalogEntryId，使用兜底实现");
        });
    }
    return fpConnectEx;
}

static void LogRuntimeConfigSummaryOnce() {
    std::call_once(g_runtimeConfigLogOnce, []() {
        const auto& config = Core::Config::Instance();

        std::string ports;
        if (config.rules.allowed_ports.empty()) {
            ports = "空(=全部)";
        } else {
            for (size_t i = 0; i < config.rules.allowed_ports.size(); i++) {
                if (i != 0) ports += ",";
                ports += std::to_string(config.rules.allowed_ports[i]);
            }
        }

        Core::Logger::Info(
            "配置摘要: proxy=" + config.proxy.type + "://" + config.proxy.host + ":" + std::to_string(config.proxy.port) +
            ", fake_ip=" + std::string(config.fakeIp.enabled ? "开" : "关") +
            ", cidr=" + config.fakeIp.cidr +
            ", dns_mode=" + (config.rules.dns_mode.empty() ? "(空)" : config.rules.dns_mode) +
            ", ipv6_mode=" + (config.rules.ipv6_mode.empty() ? "(空)" : config.rules.ipv6_mode) +
            ", udp_mode=" + (config.rules.udp_mode.empty() ? "(空)" : config.rules.udp_mode) +
            ", allowed_ports=" + ports +
            ", timeout(connect/send/recv)=" + std::to_string(config.timeout.connect_ms) + "/" + std::to_string(config.timeout.send_ms) + "/" +
                std::to_string(config.timeout.recv_ms) +
            ", child_injection=" + std::string(config.childInjection ? "开" : "关") +
            ", traffic_logging=" + std::string(config.trafficLogging ? "开" : "关")
        );
        
        // 增加系统环境信息，便于诊断不同环境下的兼容性问题
        WSADATA wsaData{};
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) == 0) {
            Core::Logger::Info("系统环境: Winsock版本=" + 
                std::to_string(LOBYTE(wsaData.wVersion)) + "." + std::to_string(HIBYTE(wsaData.wVersion)) +
                ", 最高版本=" + std::to_string(LOBYTE(wsaData.wHighVersion)) + "." + std::to_string(HIBYTE(wsaData.wHighVersion)) +
                ", MaxSockets=" + std::to_string(wsaData.iMaxSockets) +
                ", 描述=" + std::string(wsaData.szDescription));
            WSACleanup();
        }

        // 外部 IP 诊断默认关闭：只有用户显式 opt-in 时才访问 ipinfo.io，降低 release 默认联网行为面。
    });
}

static bool ResolveOriginalTarget(const sockaddr* name, std::string* host, uint16_t* port) {
    if (!name) return false;
    if (name->sa_family == AF_INET) {
        auto* addr = (sockaddr_in*)name;
        if (port) *port = ntohs(addr->sin_port);
        if (host) {
                if (Network::FakeIP::Instance().IsFakeIP(addr->sin_addr.s_addr)) {
                    std::string domain = Network::FakeIP::Instance().GetDomain(addr->sin_addr.s_addr);
                    if (domain.empty()) {
                        std::string ipStr = Network::FakeIP::IpToString(addr->sin_addr.s_addr);
                        // FakeIP::GetDomain 已在未命中时输出告警；这里降级为调试，避免重复刷屏
                        if (Core::Logger::IsEnabled(Core::LogLevel::Debug)) {
                            Core::Logger::Debug("FakeIP: 命中但映射缺失, ip=" + ipStr);
                        }
                        *host = ipStr;
                    } else {
                        *host = domain;
                    }
            } else {
                *host = Network::FakeIP::IpToString(addr->sin_addr.s_addr);
            }
        }
        return true;
    }
    if (name->sa_family == AF_INET6) {
        auto* addr6 = (sockaddr_in6*)name;
        if (port) *port = ntohs(addr6->sin6_port);
        if (host) {
            if (IN6_IS_ADDR_V4MAPPED(&addr6->sin6_addr)) {
                // IPv4-mapped IPv6 继续走 FakeIP 映射，保持域名还原能力
                in_addr addr4{};
                const unsigned char* raw = reinterpret_cast<const unsigned char*>(&addr6->sin6_addr);
                memcpy(&addr4, raw + 12, sizeof(addr4));
                if (Network::FakeIP::Instance().IsFakeIP(addr4.s_addr)) {
                    std::string domain = Network::FakeIP::Instance().GetDomain(addr4.s_addr);
                    if (domain.empty()) {
                        std::string ipStr = Network::FakeIP::IpToString(addr4.s_addr);
                        // FakeIP::GetDomain 已在未命中时输出告警；这里降级为调试，避免重复刷屏
                        if (Core::Logger::IsEnabled(Core::LogLevel::Debug)) {
                            Core::Logger::Debug("FakeIP(v4-mapped): 命中但映射缺失, ip=" + ipStr);
                        }
                        *host = ipStr;
                    } else {
                        *host = domain;
                    }
                } else {
                    *host = Network::FakeIP::IpToString(addr4.s_addr);
                }
            } else {
                char buf[INET6_ADDRSTRLEN] = {};
                if (!inet_ntop(AF_INET6, &addr6->sin6_addr, buf, sizeof(buf))) {
                    *host = "";
                } else {
                    *host = std::string(buf);
                }
            }
        }
        return true;
    }
    return false;
}

static bool IsLoopbackHost(const std::string& host) {
    return Network::IsLoopbackHost(host);
}

// 判断是否为 IP 字面量（IPv4/IPv6），避免对纯 IP 走 FakeIP 影响原始语义
static bool IsIpLiteralHost(const std::string& host) {
    in_addr addr4{};
    if (inet_pton(AF_INET, host.c_str(), &addr4) == 1) return true;
    in6_addr addr6{};
    if (inet_pton(AF_INET6, host.c_str(), &addr6) == 1) return true;
    return false;
}

// 将 sockaddr 转成可读地址，便于日志排查
static std::string SockaddrToString(const sockaddr* addr) {
    if (!addr) return "";
    if (addr->sa_family == AF_INET) {
        const auto* addr4 = (const sockaddr_in*)addr;
        char buf[INET_ADDRSTRLEN] = {};
        if (!inet_ntop(AF_INET, &addr4->sin_addr, buf, sizeof(buf))) return "";
        return std::string(buf) + ":" + std::to_string(ntohs(addr4->sin_port));
    }
    if (addr->sa_family == AF_INET6) {
        const auto* addr6 = (const sockaddr_in6*)addr;
        char buf[INET6_ADDRSTRLEN] = {};
        if (!inet_ntop(AF_INET6, &addr6->sin6_addr, buf, sizeof(buf))) return "";
        return std::string(buf) + ":" + std::to_string(ntohs(addr6->sin6_port));
    }
    return "";
}

static void LogLocalTargetBypass(const char* api, SOCKET s, const std::string& target) {
    Core::Logger::Info("本地目标全透明旁路: api=" + std::string(api) +
                       ", sock=" + std::to_string((unsigned long long)s) +
                       ", target=" + (target.empty() ? std::string("(未知)") : target));
}

// 从 sockaddr 提取纯 IP（不含端口）
static bool SockaddrToIp(const sockaddr* addr, std::string* outIp, bool* outIsV6) {
    if (!addr || !outIp) return false;
    if (outIsV6) *outIsV6 = false;
    if (addr->sa_family == AF_INET) {
        const auto* addr4 = (const sockaddr_in*)addr;
        char buf[INET_ADDRSTRLEN] = {};
        if (!inet_ntop(AF_INET, &addr4->sin_addr, buf, sizeof(buf))) return false;
        *outIp = std::string(buf);
        return true;
    }
    if (addr->sa_family == AF_INET6) {
        const auto* addr6 = (const sockaddr_in6*)addr;
        if (IN6_IS_ADDR_V4MAPPED(&addr6->sin6_addr)) {
            in_addr addr4{};
            const unsigned char* raw = reinterpret_cast<const unsigned char*>(&addr6->sin6_addr);
            memcpy(&addr4, raw + 12, sizeof(addr4));
            char buf4[INET_ADDRSTRLEN] = {};
            if (!inet_ntop(AF_INET, &addr4, buf4, sizeof(buf4))) return false;
            *outIp = std::string(buf4);
            if (outIsV6) *outIsV6 = false;
            return true;
        }
        char buf[INET6_ADDRSTRLEN] = {};
        if (!inet_ntop(AF_INET6, &addr6->sin6_addr, buf, sizeof(buf))) return false;
        *outIp = std::string(buf);
        if (outIsV6) *outIsV6 = true;
        return true;
    }
    return false;
}

// 从 sockaddr 提取端口（仅用于策略判断/日志；失败时返回 false）
static bool TryGetSockaddrPort(const sockaddr* addr, uint16_t* outPort) {
    if (!outPort) return false;
    *outPort = 0;
    if (!addr) return false;
    if (addr->sa_family == AF_INET) {
        const auto* addr4 = (const sockaddr_in*)addr;
        *outPort = ntohs(addr4->sin_port);
        return true;
    }
    if (addr->sa_family == AF_INET6) {
        const auto* addr6 = (const sockaddr_in6*)addr;
        *outPort = ntohs(addr6->sin6_port);
        return true;
    }
    return false;
}

// 判断 sockaddr 是否为回环地址（127.0.0.0/8 或 ::1 或 v4-mapped 127.0.0.0/8）
static bool IsSockaddrLoopback(const sockaddr* addr) {
    if (!addr) return false;
    const int addressLength = addr->sa_family == AF_INET
        ? static_cast<int>(sizeof(sockaddr_in))
        : addr->sa_family == AF_INET6
            ? static_cast<int>(sizeof(sockaddr_in6))
            : static_cast<int>(sizeof(sockaddr));
    return Network::IsLocalSockaddr(addr, addressLength);
}

// UDP 强阻断策略会触发大量重试（尤其是 QUIC），这里做简单限流，避免日志/IO 影响性能
static bool ShouldLogUdpBlock() {
    static std::atomic<int> s_logCount{0};
    const int n = s_logCount.fetch_add(1, std::memory_order_relaxed);
    if (n < 20) return true; // 仅前 20 次输出详细阻断日志
    if (n == 20) {
        Core::Logger::Warn("UDP 阻断日志过多，后续将仅在 [调试] 级别输出（避免 QUIC 重试导致日志/性能问题；注意：WSA错误码为策略阻断返回，并非真实网络故障）");
    }
    return Core::Logger::IsEnabled(Core::LogLevel::Debug);
}

// UDP 代理失败可能会触发 QUIC 的高频重试，这里同样做简单限流，避免日志/IO 影响性能
static bool ShouldLogUdpProxyFail() {
    static std::atomic<int> s_failCount{0};
    const int n = s_failCount.fetch_add(1, std::memory_order_relaxed);
    if (n < 20) return true;
    if (n == 20) {
        Core::Logger::Warn("UDP 代理失败日志过多，后续将仅在 [调试] 级别输出（避免 QUIC 重试导致日志/性能问题）");
    }
    return Core::Logger::IsEnabled(Core::LogLevel::Debug);
}

// UDP 有效策略为 block 时的放行例外（Issue #169）：
// loopback、UDP/53，以及命中 direct 路由规则的目标（含 use_default_private 内置的局域网/保留网段）。
// 意图：block 只阻止 UDP 走公网，局域网 P2P（如 WebRTC host 候选）应与 TCP 一样直连。
// 仅“命中规则且动作为 direct”才放行；未命中时的 default_action 不参与，避免 default_action=direct 让 block 失效。
static bool IsUdpBlockExempt(const Core::Config& config, const sockaddr* dst, bool hasPort, uint16_t dstPort) {
    if (!dst) return false;
    if (IsSockaddrLoopback(dst) || (hasPort && dstPort == 53 && config.rules.dns_mode == "direct")) return true;

    std::string ip;
    bool isV6 = false;
    if (!SockaddrToIp(dst, &ip, &isV6)) return false;
    std::string action;
    return config.rules.MatchRouting("", ip, isV6, dstPort, "udp", &action, nullptr) && action == "direct";
}

// connect/ConnectEx 属于高频热路径，路由日志默认做限流，避免 Info 级别大量刷盘
static bool ShouldLogRouteDecisionInfo() {
    static std::atomic<int> s_routeCount{0};
    const int n = s_routeCount.fetch_add(1, std::memory_order_relaxed);
    if (n < 200) return true;
    if (n == 200) {
        Core::Logger::Info("路由决策日志过多，后续将仅在 [调试] 级别输出（避免高并发场景日志 I/O 影响性能）");
    }
    return Core::Logger::IsEnabled(Core::LogLevel::Debug);
}

// 从 socket 读取当前端点信息（仅用于日志；失败时返回空字符串）
static std::string GetPeerEndpoint(SOCKET s) {
    sockaddr_storage ss{};
    int len = (int)sizeof(ss);
    if (getpeername(s, (sockaddr*)&ss, &len) != 0) return "";
    return SockaddrToString((sockaddr*)&ss);
}

static std::string GetLocalEndpoint(SOCKET s) {
    sockaddr_storage ss{};
    int len = (int)sizeof(ss);
    if (getsockname(s, (sockaddr*)&ss, &len) != 0) return "";
    return SockaddrToString((sockaddr*)&ss);
}

static bool IsProxySelfTarget(const std::string& host, uint16_t port, const Core::ProxyConfig& proxy) {
    return port == proxy.port && (host == proxy.host || host == "127.0.0.1");
}

static std::string ProxyEndpointToString(const sockaddr_storage& ss) {
    return SockaddrToString((const sockaddr*)&ss);
}

static bool AppendProxyEndpoint(const sockaddr* addr, int addrLen, int desiredFamily,
                                std::vector<sockaddr_storage>* out, std::vector<int>* outLens) {
    if (!addr || !out || !outLens) return false;
    if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6) return false;

    sockaddr_storage ss{};
    int len = 0;
    if (addr->sa_family == AF_INET) {
        if (addrLen < (int)sizeof(sockaddr_in)) return false;
        if (desiredFamily == AF_INET6) {
            // 目标 socket 是 IPv6 时，将 IPv4 代理端点映射为 v4-mapped IPv6，兼容双栈 socket。
            const auto* a4 = (const sockaddr_in*)addr;
            sockaddr_in6 mapped{};
            mapped.sin6_family = AF_INET6;
            mapped.sin6_port = a4->sin_port;
            memset(&mapped.sin6_addr, 0, sizeof(mapped.sin6_addr));
            mapped.sin6_addr.u.Byte[10] = 0xff;
            mapped.sin6_addr.u.Byte[11] = 0xff;
            memcpy(&mapped.sin6_addr.u.Byte[12], &a4->sin_addr, sizeof(a4->sin_addr));
            memcpy(&ss, &mapped, sizeof(mapped));
            len = (int)sizeof(mapped);
        } else {
            memcpy(&ss, addr, sizeof(sockaddr_in));
            len = (int)sizeof(sockaddr_in);
        }
    } else {
        if (addrLen < (int)sizeof(sockaddr_in6)) return false;
        if (desiredFamily == AF_INET) return false;
        memcpy(&ss, addr, sizeof(sockaddr_in6));
        len = (int)sizeof(sockaddr_in6);
    }

    for (size_t i = 0; i < out->size(); ++i) {
        if ((*outLens)[i] == len && memcmp(&(*out)[i], &ss, (size_t)len) == 0) {
            return true;
        }
    }

    out->push_back(ss);
    outLens->push_back(len);
    return true;
}

static bool ResolveProxyEndpoints(const Core::ProxyConfig& proxy, int desiredFamily,
                                  std::vector<sockaddr_storage>* out, std::vector<int>* outLens) {
    if (!out || !outLens) return false;
    out->clear();
    outLens->clear();
    if (proxy.host.empty() || proxy.port <= 0 || proxy.port > 65535) {
        Core::Logger::Error("代理地址无效: host=" + proxy.host + ", port=" + std::to_string(proxy.port));
        return false;
    }

    in_addr addr4{};
    if (inet_pton(AF_INET, proxy.host.c_str(), &addr4) == 1) {
        sockaddr_in a4{};
        a4.sin_family = AF_INET;
        a4.sin_port = htons(static_cast<u_short>(proxy.port));
        a4.sin_addr = addr4;
        AppendProxyEndpoint((sockaddr*)&a4, (int)sizeof(a4), desiredFamily, out, outLens);
        return !out->empty();
    }

    in6_addr addr6{};
    if (inet_pton(AF_INET6, proxy.host.c_str(), &addr6) == 1) {
        if (desiredFamily == AF_INET) {
            Core::Logger::Error("代理地址族不兼容: IPv4 socket 无法连接 IPv6 代理 " + proxy.host);
            return false;
        }
        sockaddr_in6 a6{};
        a6.sin6_family = AF_INET6;
        a6.sin6_port = htons(static_cast<u_short>(proxy.port));
        a6.sin6_addr = addr6;
        AppendProxyEndpoint((sockaddr*)&a6, (int)sizeof(a6), desiredFamily, out, outLens);
        return !out->empty();
    }

    addrinfo hints{};
    hints.ai_family = desiredFamily == AF_INET ? AF_INET : AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo* res = nullptr;
    int rc = fpGetAddrInfo ? fpGetAddrInfo(proxy.host.c_str(), nullptr, &hints, &res)
                           : getaddrinfo(proxy.host.c_str(), nullptr, &hints, &res);
    if (rc != 0 || !res) {
        Core::Logger::Error("代理地址解析失败: " + proxy.host + ", 错误码=" + std::to_string(rc));
        return false;
    }

    for (addrinfo* it = res; it; it = it->ai_next) {
        if (!it->ai_addr) continue;
        if (it->ai_addr->sa_family == AF_INET) {
            auto a4 = *(sockaddr_in*)it->ai_addr;
            a4.sin_port = htons(static_cast<u_short>(proxy.port));
            AppendProxyEndpoint((sockaddr*)&a4, (int)sizeof(a4), desiredFamily, out, outLens);
        } else if (it->ai_addr->sa_family == AF_INET6) {
            auto a6 = *(sockaddr_in6*)it->ai_addr;
            a6.sin6_port = htons(static_cast<u_short>(proxy.port));
            AppendProxyEndpoint((sockaddr*)&a6, (int)sizeof(a6), desiredFamily, out, outLens);
        }
    }
    freeaddrinfo(res);

    if (out->empty()) {
        Core::Logger::Error("代理地址解析无可用结果: " + proxy.host);
        return false;
    }
    return true;
}

static bool BuildProxyAddr(const Core::ProxyConfig& proxy, sockaddr_in* proxyAddr, const sockaddr_in* baseAddr) {
    if (!proxyAddr) return false;
    if (baseAddr) {
        *proxyAddr = *baseAddr;
    } else {
        memset(proxyAddr, 0, sizeof(sockaddr_in));
        proxyAddr->sin_family = AF_INET;
    }
    std::vector<sockaddr_storage> endpoints;
    std::vector<int> endpointLens;
    if (!ResolveProxyEndpoints(proxy, AF_INET, &endpoints, &endpointLens)) {
        return false;
    }
    memcpy(proxyAddr, &endpoints[0], sizeof(sockaddr_in));
    proxyAddr->sin_port = htons(static_cast<u_short>(proxy.port));
    return true;
}

static bool BuildProxyAddrV6(const Core::ProxyConfig& proxy, sockaddr_in6* proxyAddr, const sockaddr_in6* baseAddr) {
    if (!proxyAddr) return false;
    if (baseAddr) {
        *proxyAddr = *baseAddr;
    } else {
        memset(proxyAddr, 0, sizeof(sockaddr_in6));
    }
    proxyAddr->sin6_family = AF_INET6;

    std::vector<sockaddr_storage> endpoints;
    std::vector<int> endpointLens;
    if (!ResolveProxyEndpoints(proxy, AF_INET6, &endpoints, &endpointLens)) {
        return false;
    }
    memcpy(proxyAddr, &endpoints[0], sizeof(sockaddr_in6));
    proxyAddr->sin6_port = htons(static_cast<u_short>(proxy.port));
    return true;
}

// ============= UDP 代理辅助函数 =============

static size_t SumWsabufBytes(const WSABUF* bufs, DWORD count) {
    size_t total = 0;
    if (!bufs) return 0;
    for (DWORD i = 0; i < count; ++i) {
        total += (size_t)bufs[i].len;
    }
    return total;
}

static size_t CopyBytesToWsabufs(const uint8_t* src, size_t srcLen, WSABUF* dstBufs, DWORD dstCount) {
    if (!src || srcLen == 0 || !dstBufs || dstCount == 0) return 0;
    size_t copied = 0;
    for (DWORD i = 0; i < dstCount && copied < srcLen; ++i) {
        char* dst = dstBufs[i].buf;
        size_t cap = (size_t)dstBufs[i].len;
        if (!dst || cap == 0) continue;
        const size_t n = (srcLen - copied < cap) ? (srcLen - copied) : cap;
        memcpy(dst, src + copied, n);
        copied += n;
    }
    return copied;
}

static bool SendUdpPacketWithRetry(SOCKET s, const uint8_t* data, int len, int flags, int timeoutMs) {
    if (!data || len <= 0) return true;
    if (!fpSend) {
        WSASetLastError(WSAEINVAL);
        return false;
    }
    for (;;) {
        int sent = fpSend(s, (const char*)data, len, flags);
        if (sent == len) {
            return true;
        }
        if (sent > 0) {
            // UDP 理论上不应 partial send；这里按失败处理，避免上层误判
            WSASetLastError(WSAEMSGSIZE);
            return false;
        }
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK || err == WSAEINPROGRESS) {
            if (!Network::SocketIo::WaitWritable(s, timeoutMs)) return false;
            continue;
        }
        WSASetLastError(err);
        return false;
    }
}

static bool FillUserSockaddr(sockaddr* userFrom, LPINT userFromLen, const sockaddr_storage& src, int srcLen) {
    if (!userFromLen) return false;
    if (!userFrom) {
        // 用户没传 buffer，只能回填长度
        *userFromLen = srcLen;
        return true;
    }
    if (*userFromLen < srcLen) {
        // buffer 不足：按 WSARecvFrom 语义，返回错误由调用方处理，这里仅回填需要的长度
        *userFromLen = srcLen;
        return false;
    }
    if (srcLen > 0) {
        memcpy(userFrom, &src, (size_t)srcLen);
        *userFromLen = srcLen;
        return true;
    }
    *userFromLen = 0;
    return true;
}

static bool BuildUdpRelayAddrForSocketFamily(int socketFamily, const sockaddr_storage& relay, int relayLen,
                                             sockaddr_storage* out, int* outLen) {
    if (!out || !outLen || relayLen <= 0) return false;
    memset(out, 0, sizeof(sockaddr_storage));
    *outLen = 0;

    if (socketFamily == AF_INET) {
        if (relay.ss_family == AF_INET && relayLen >= (int)sizeof(sockaddr_in)) {
            memcpy(out, &relay, sizeof(sockaddr_in));
            *outLen = (int)sizeof(sockaddr_in);
            return true;
        }
        // IPv4 socket 无法直接 connect IPv6 relay
        return false;
    }

    if (socketFamily == AF_INET6) {
        if (relay.ss_family == AF_INET6 && relayLen >= (int)sizeof(sockaddr_in6)) {
            memcpy(out, &relay, sizeof(sockaddr_in6));
            *outLen = (int)sizeof(sockaddr_in6);
            return true;
        }
        if (relay.ss_family == AF_INET && relayLen >= (int)sizeof(sockaddr_in)) {
            // IPv4 relay 映射为 v4-mapped IPv6（兼容双栈 UDP socket）
            const auto* a4 = (const sockaddr_in*)&relay;
            sockaddr_in6 mapped{};
            mapped.sin6_family = AF_INET6;
            mapped.sin6_port = a4->sin_port;
            memset(&mapped.sin6_addr, 0, sizeof(mapped.sin6_addr));
            mapped.sin6_addr.u.Byte[10] = 0xff;
            mapped.sin6_addr.u.Byte[11] = 0xff;
            memcpy(&mapped.sin6_addr.u.Byte[12], &a4->sin_addr, sizeof(a4->sin_addr));
            memcpy(out, &mapped, sizeof(mapped));
            *outLen = (int)sizeof(mapped);
            return true;
        }
        return false;
    }

    return false;
}

static SOCKET ConnectTcpToProxyServer(const Core::ProxyConfig& proxy) {
    // 说明：UDP Associate 需要一个到代理的 TCP 控制连接
    // 使用 AF_UNSPEC 解析并逐个候选尝试，支持 hyperv.mshome.net 这类 DHCP/本地域名。
    std::vector<sockaddr_storage> endpoints;
    std::vector<int> endpointLens;
    if (!ResolveProxyEndpoints(proxy, AF_UNSPEC, &endpoints, &endpointLens)) {
        return INVALID_SOCKET;
    }

    auto& config = Core::Config::Instance();
    int lastErr = 0;
    for (size_t i = 0; i < endpoints.size(); ++i) {
        const int family = endpoints[i].ss_family;
        SOCKET tcpSock = socket(family, SOCK_STREAM, IPPROTO_TCP);
        if (tcpSock == INVALID_SOCKET) {
            lastErr = WSAGetLastError();
            Core::Logger::Warn("SOCKS5 UDP: 创建 TCP 控制连接失败, endpoint=" + ProxyEndpointToString(endpoints[i]) +
                               ", WSA错误码=" + std::to_string(lastErr));
            continue;
        }

        // 非阻塞 connect + WaitConnect，避免卡死目标进程
        u_long nb = 1;
        ioctlsocket(tcpSock, FIONBIO, &nb);

        int rc = fpConnect ? fpConnect(tcpSock, (sockaddr*)&endpoints[i], endpointLens[i])
                           : connect(tcpSock, (sockaddr*)&endpoints[i], endpointLens[i]);
        if (rc != 0) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK || err == WSAEINPROGRESS) {
                if (!Network::SocketIo::WaitConnect(tcpSock, config.timeout.connect_ms)) {
                    err = WSAGetLastError();
                    Core::Logger::Warn("SOCKS5 UDP: 连接代理候选失败, endpoint=" + ProxyEndpointToString(endpoints[i]) +
                                       ", WSA错误码=" + std::to_string(err));
                    CloseSocketCompat(tcpSock);
                    lastErr = err;
                    continue;
                }
            } else {
                Core::Logger::Warn("SOCKS5 UDP: 连接代理候选失败, endpoint=" + ProxyEndpointToString(endpoints[i]) +
                                   ", WSA错误码=" + std::to_string(err));
                CloseSocketCompat(tcpSock);
                lastErr = err;
                continue;
            }
        }

        // 连接完成后切回阻塞：后续握手使用 SocketIo::SendAll/RecvExact（内部兼容 EWOULDBLOCK）
        nb = 0;
        ioctlsocket(tcpSock, FIONBIO, &nb);
        if (Core::Logger::IsEnabled(Core::LogLevel::Debug)) {
            Core::Logger::Debug("SOCKS5 UDP: 已连接代理候选, endpoint=" + ProxyEndpointToString(endpoints[i]));
        }
        return tcpSock;
    }

    if (lastErr != 0) WSASetLastError(lastErr);
    Core::Logger::Error("SOCKS5 UDP: 所有代理候选均连接失败, proxy=" + proxy.host + ":" + std::to_string(proxy.port) +
                        (lastErr ? ", 最后WSA错误码=" + std::to_string(lastErr) : std::string("")));
    return INVALID_SOCKET;
}

static void DropUdpOverlappedContext(LPWSAOVERLAPPED ovl) {
    if (!ovl) return;
    std::lock_guard<std::mutex> lock(g_udpOvlMtx);
    g_udpOvlSend.erase(ovl);
    g_udpOvlRecv.erase(ovl);
    g_udpCompleted.erase(ovl);
}


static void CleanupUdpOverlappedBySocket(SOCKET s) {
    std::lock_guard<std::mutex> lock(g_udpOvlMtx);
    for (auto it=g_udpCompleted.begin(); it!=g_udpCompleted.end();) {
        if (it->second.sock==s) it=g_udpCompleted.erase(it); else ++it;
    }
    // closesocket initiates cancellation but does not wait for the provider to stop
    // writing. Pending buffers are released by the eventual completion consumer.
    for(auto it=g_udpOvlSend.begin();it!=g_udpOvlSend.end();) {
        auto context=it->second;
        if(context && context->sock==s) {
            std::lock_guard<std::mutex> guard(context->completionMutex);
            if(context->completed) { it=g_udpOvlSend.erase(it); continue; }
            context->sock=INVALID_SOCKET;
        }
        ++it;
    }
    for(auto it=g_udpOvlRecv.begin();it!=g_udpOvlRecv.end();) {
        auto context=it->second;
        if(context && context->sock==s) {
            std::lock_guard<std::mutex> guard(context->completionMutex);
            if(context->completed) { it=g_udpOvlRecv.erase(it); continue; }
            context->sock=INVALID_SOCKET;
        }
        ++it;
    }
}

static void CleanupUdpProxyContext(SOCKET s) {
    SOCKET control = INVALID_SOCKET;
    {
        std::lock_guard<std::mutex> lock(g_udpProxyMtx);
        auto it = g_udpProxy.find(s);
        if (it != g_udpProxy.end()) {
            control = it->second.controlSock;
            g_udpProxy.erase(it);
        }
    }
    if (control != INVALID_SOCKET) {
        // 关闭控制连接：使用原始 closesocket，避免递归进入 DetourCloseSocket
        if (fpCloseSocket) fpCloseSocket(control);
        else closesocket(control);
    }
    CleanupUdpOverlappedBySocket(s);
}

// 进程级 UDP ASSOCIATE 失败退避：代理未开启 UDP 时 60 秒内不再重复尝试（见 UdpAssociateBackoff.hpp）
static Network::UdpAssociateBackoff g_udpAssociateBackoff;

// 记录 ASSOCIATE 失败；每个退避窗口只输出一次可操作的提示，替代逐个 socket 的重复错误
static void NoteUdpAssociateUnavailable(const char* reason) {
    if (!g_udpAssociateBackoff.RecordFailure(GetTickCount64())) return;
    const auto& config = Core::Config::Instance();
    Core::Logger::Warn(std::string("SOCKS5 UDP 不可用（") + reason + "）：60 秒内不再尝试，UDP 按 udp_fallback=" +
                       config.rules.udp_fallback + " 处理（QUIC/HTTP3 会自动回退到 TCP，不影响正常使用）。" +
                       "如需 UDP，请在代理软件中开启 SOCKS5 的 UDP 支持（例如 v2rayN 入站的「启用 UDP」），" +
                       "或把 proxy_rules.udp_mode 设为 block 关闭 UDP 代理尝试。");
}

static bool EnsureUdpProxyReady(
    SOCKET udpSock,
    int socketFamily,
    const std::string& defaultTargetHost,
    uint16_t defaultTargetPort,
    bool connectRelay = true
) {
    auto& config = Core::Config::Instance();
    if (udpSock == INVALID_SOCKET) {
        WSASetLastError(WSAEINVAL);
        return false;
    }

    if (config.proxy.port == 0) {
        WSASetLastError(WSAEINVAL);
        return false;
    }

    // UDP 代理仅支持 SOCKS5（HTTP 代理没有标准的 UDP 转发能力）
    if (config.proxy.type != "socks5") {
        if (ShouldLogUdpProxyFail()) {
            Core::Logger::Warn("UDP 代理仅支持 SOCKS5 (UDP Associate)。当前 proxy.type=" + config.proxy.type +
                               "；若需 QUIC/HTTP3 请改用 socks5。将按 udp_fallback=" + config.rules.udp_fallback + " 处理。");
        }
        WSASetLastError(WSAEACCES);
        return false;
    }

    // 1) 确保存在 UDP Associate 控制连接 + relay 地址
    // 性能优化：阻塞 I/O（connect/UdpAssociate）放到锁外执行，降低 g_udpProxyMtx 竞争
    bool needCreateContext = false;
    {
        std::lock_guard<std::mutex> lock(g_udpProxyMtx);
        auto it = g_udpProxy.find(udpSock);
        if (it == g_udpProxy.end()) {
            needCreateContext = true;
        } else if (!defaultTargetHost.empty() && defaultTargetPort != 0) {
            it->second.defaultTargetHost = defaultTargetHost;
            it->second.defaultTargetPort = defaultTargetPort;
            it->second.hasDefaultTarget = true;
        }
    }

    if (needCreateContext) {
        // 退避期内（代理刚确认不支持 UDP）直接失败，交给调用方按 udp_fallback 处理，不再重复握手与刷日志
        const ULONGLONG nowTick = GetTickCount64();
        if (g_udpAssociateBackoff.ShouldSkip(nowTick)) {
            WSASetLastError(WSAECONNREFUSED);
            return false;
        }

        UdpProxyContext created{};
        created.udpSock = udpSock;
        created.createdTick = nowTick;

        SOCKET tcp = ConnectTcpToProxyServer(config.proxy);
        if (tcp == INVALID_SOCKET) {
            NoteUdpAssociateUnavailable("无法连接代理服务器");
            WSASetLastError(WSAECONNREFUSED);
            return false;
        }

        Network::Socks5Udp::UdpAssociateResult assoc{};
        if (!Network::Socks5Udp::UdpAssociate(tcp, nullptr, 0, &assoc)) {
            if (fpCloseSocket) fpCloseSocket(tcp);
            else closesocket(tcp);
            NoteUdpAssociateUnavailable("代理拒绝或不支持 UDP ASSOCIATE");
            WSASetLastError(WSAECONNREFUSED);
            return false;
        }
        g_udpAssociateBackoff.RecordSuccess();

        created.controlSock = tcp;
        created.relayAddr = assoc.relayAddr;
        created.relayAddrLen = assoc.relayAddrLen;
        created.relayConnected = false;
        if (!defaultTargetHost.empty() && defaultTargetPort != 0) {
            created.defaultTargetHost = defaultTargetHost;
            created.defaultTargetPort = defaultTargetPort;
            created.hasDefaultTarget = true;
        }

        SOCKET orphanControl = INVALID_SOCKET;
        {
            std::lock_guard<std::mutex> lock(g_udpProxyMtx);
            auto it = g_udpProxy.find(udpSock);
            if (it == g_udpProxy.end()) {
                g_udpProxy[udpSock] = std::move(created);
            } else {
                // 并发场景下若已被其他线程初始化，复用已有上下文并关闭当前临时控制连接
                orphanControl = created.controlSock;
                if (!defaultTargetHost.empty() && defaultTargetPort != 0) {
                    it->second.defaultTargetHost = defaultTargetHost;
                    it->second.defaultTargetPort = defaultTargetPort;
                    it->second.hasDefaultTarget = true;
                }
            }
        }
        if (orphanControl != INVALID_SOCKET) {
            if (fpCloseSocket) fpCloseSocket(orphanControl);
            else closesocket(orphanControl);
        }
    }

    // 2) 确保 UDP socket 已 connect 到 relay（让 select/IOCP/readiness 与原 socket 绑定，满足 QUIC 等高性能实现）
    // 说明：ConnectEx(UDP) 场景下会由 original ConnectEx 完成 connect，此处允许跳过。
    if (!connectRelay) {
        return true;
    }
    sockaddr_storage relayForSock{};
    int relayForSockLen = 0;
    {
        std::lock_guard<std::mutex> lock(g_udpProxyMtx);
        auto it = g_udpProxy.find(udpSock);
        if (it == g_udpProxy.end()) {
            WSASetLastError(WSAECONNREFUSED);
            return false;
        }
        if (it->second.relayConnected) {
            return true;
        }
        if (!BuildUdpRelayAddrForSocketFamily(socketFamily, it->second.relayAddr, it->second.relayAddrLen, &relayForSock, &relayForSockLen)) {
            Core::Logger::Error("UDP 代理: relay 地址族不兼容, sock=" + std::to_string((unsigned long long)udpSock) +
                                ", socketFamily=" + std::to_string(socketFamily) +
                                ", relayFamily=" + std::to_string((int)it->second.relayAddr.ss_family));
            WSASetLastError(WSAEAFNOSUPPORT);
            return false;
        }
    }

    if (relayForSock.ss_family == AF_INET6 &&
        !PrepareIpv4MappedProxyDestination(
            udpSock,
            *reinterpret_cast<const sockaddr_in6*>(&relayForSock))) {
        return false;
    }

    int rc = fpConnect ? fpConnect(udpSock, (sockaddr*)&relayForSock, relayForSockLen)
                       : connect(udpSock, (sockaddr*)&relayForSock, relayForSockLen);
    if (rc != 0) {
        const int err = WSAGetLastError();
        // 并发场景下可能已被其它线程先 connect，WSAEISCONN 视为成功
        if (err != WSAEISCONN) {
            // Issue #169：失败会随每个 UDP 包重复出现，改为限流输出；
            // 同时打印 socket 本地绑定地址与 relay 地址，用于确认“已绑定到网卡 IP 的 socket 无法连接本机 relay”（10049）
            if (ShouldLogUdpProxyFail()) {
                sockaddr_storage local{};
                int localLen = (int)sizeof(local);
                const std::string localStr = (getsockname(udpSock, (sockaddr*)&local, &localLen) == 0)
                    ? SockaddrToString((sockaddr*)&local) : std::string();
                const std::string relayStr = SockaddrToString((sockaddr*)&relayForSock);
                Core::Logger::Error("UDP 代理: connect relay 失败, sock=" + std::to_string((unsigned long long)udpSock) +
                                    ", local=" + (localStr.empty() ? std::string("(未知)") : localStr) +
                                    ", relay=" + (relayStr.empty() ? std::string("(未知)") : relayStr) +
                                    ", WSA错误码=" + std::to_string(err) +
                                    (err == WSAEADDRNOTAVAIL
                                         ? "（socket 可能已绑定到非回环网卡地址，无法连接本机 relay；将按 udp_fallback=" +
                                               config.rules.udp_fallback + " 处理）"
                                         : std::string()));
            }
            WSASetLastError(err);
            return false;
        }
    }

    bool newlyConnected = false;
    {
        std::lock_guard<std::mutex> lock(g_udpProxyMtx);
        auto it = g_udpProxy.find(udpSock);
        if (it == g_udpProxy.end()) {
            WSASetLastError(WSAECONNREFUSED);
            return false;
        }
        newlyConnected = !it->second.relayConnected;
        it->second.relayConnected = true;
    }

    // 仅在首次 connect relay 时输出，避免刷屏
    if (newlyConnected) {
        const std::string relayStr = SockaddrToString((sockaddr*)&relayForSock);
        Core::Logger::Info("UDP 代理 relay 已连接, sock=" + std::to_string((unsigned long long)udpSock) +
                           (relayStr.empty() ? "" : (", relay=" + relayStr)));
    }
    return true;
}

static bool TryGetUdpProxyDefaultTarget(SOCKET s, std::string* outHost, uint16_t* outPort) {
    if (outHost) outHost->clear();
    if (outPort) *outPort = 0;
    std::lock_guard<std::mutex> lock(g_udpProxyMtx);
    auto it = g_udpProxy.find(s);
    if (it == g_udpProxy.end()) return false;
    if (!it->second.hasDefaultTarget) return false;
    if (outHost) *outHost = it->second.defaultTargetHost;
    if (outPort) *outPort = it->second.defaultTargetPort;
    return true;
}

static void UpdateUdpProxyDefaultTarget(SOCKET s, const std::string& host, uint16_t port) {
    if (s == INVALID_SOCKET || host.empty() || port == 0) return;
    std::lock_guard<std::mutex> lock(g_udpProxyMtx);
    auto it = g_udpProxy.find(s);
    if (it == g_udpProxy.end()) return;
    it->second.defaultTargetHost = host;
    it->second.defaultTargetPort = port;
    it->second.hasDefaultTarget = true;
}

static bool TryGetUdpRelayAddr(SOCKET s, sockaddr_storage* out, int* outLen) {
    if (!out || !outLen) return false;
    std::lock_guard<std::mutex> lock(g_udpProxyMtx);
    auto it = g_udpProxy.find(s);
    if (it == g_udpProxy.end()) return false;
    if (it->second.relayAddrLen <= 0) return false;
    *out = it->second.relayAddr;
    *outLen = it->second.relayAddrLen;
    return true;
}

static void MarkUdpRelayConnected(SOCKET s) {
    std::lock_guard<std::mutex> lock(g_udpProxyMtx);
    auto it = g_udpProxy.find(s);
    if (it == g_udpProxy.end()) return;
    it->second.relayConnected = true;
}


static bool IsSocketConnected(SOCKET s) {
    sockaddr_storage peer{}; int length=sizeof(peer);
    return getpeername(s,reinterpret_cast<sockaddr*>(&peer),&length)==0;
}
// sendto must not connect an originally unconnected socket. Use an explicit
// relay destination and only retain a default target for genuinely connected I/O.
static bool PrepareUdpDatagramRelay(SOCKET s, int family, const std::string& host, uint16_t port,
    sockaddr_storage* relay, int* relayLength) {
    bool connected=IsSocketConnected(s);
    WSAPROTOCOL_INFOW info{}; int size=sizeof(info);
    if(getsockopt(s,SOL_SOCKET,SO_PROTOCOL_INFOW,reinterpret_cast<char*>(&info),&size)==0) family=info.iAddressFamily;
    if(!EnsureUdpProxyReady(s,family,connected?host:std::string(),connected?port:0,connected)) return false;
    sockaddr_storage native{}; int nativeLength=0;
    if(!TryGetUdpRelayAddr(s,&native,&nativeLength) ||
       !BuildUdpRelayAddrForSocketFamily(family,native,nativeLength,relay,relayLength)) {
        WSASetLastError(WSAEAFNOSUPPORT); return false;
    }
    if(connected) UpdateUdpProxyDefaultTarget(s,host,port);
    return true;
}
static bool DecodeUdpDatagram(SOCKET s, const uint8_t* data, size_t size,
    const sockaddr* source, int sourceLength, Network::Socks5Udp::UnwrapResult* result) {
    if(source && (source->sa_family==AF_INET || source->sa_family==AF_INET6)) {
        sockaddr_storage relay{}, compatible{}; int relayLength=0,compatibleLength=0;
        bool fromRelay=TryGetUdpRelayAddr(s,&relay,&relayLength) &&
            BuildUdpRelayAddrForSocketFamily(source->sa_family,relay,relayLength,&compatible,&compatibleLength) &&
            SockaddrToString(source)==SockaddrToString(reinterpret_cast<sockaddr*>(&compatible));
        // One unconnected socket may receive both relay and local/direct replies.
        if(!fromRelay) {
            if(sourceLength<=0 || sourceLength>static_cast<int>(sizeof(result->src))) return false;
            *result={}; result->payload=data; result->payloadLen=size;
            memcpy(&result->src,source,sourceLength); result->srcLen=sourceLength;
            return true;
        }
    }
    return Network::Socks5Udp::Unwrap(data,size,result);
}

static bool HandleUdpOverlappedCompletion(LPWSAOVERLAPPED ovl,DWORD internalBytes,DWORD* outBytes,
    int* outError=nullptr, bool consume=false) {
    if(outError) *outError=0;
    if(!ovl) return false;
    std::shared_ptr<UdpOverlappedSendCtx> send;
    std::shared_ptr<UdpOverlappedRecvCtx> receive;
    {
        std::lock_guard<std::mutex> lock(g_udpOvlMtx);
        auto completed=g_udpCompleted.find(ovl);
        if(completed!=g_udpCompleted.end()) {
            if(outBytes) *outBytes=completed->second.bytes;
            if(outError) *outError=completed->second.error;
            if(consume) g_udpCompleted.erase(completed);
            return true;
        }
        auto sent=g_udpOvlSend.find(ovl);
        if(sent!=g_udpOvlSend.end()) send=sent->second;
        auto received=g_udpOvlRecv.find(ovl);
        if(received!=g_udpOvlRecv.end()) receive=received->second;
    }
    UdpCompletedResult result;
    if(send) {
        std::lock_guard<std::mutex> lock(send->completionMutex);
        if(!send->completed) {
            send->completed=true; send->completedBytes=send->userBytes;
            ovl->InternalHigh=send->userBytes;
            std::vector<uint8_t>().swap(send->header);
            std::vector<WSABUF>().swap(send->bufs);
        }
        result={send->sock,send->completedBytes,0,send->userCompletion};
    } else if(receive) {
        std::lock_guard<std::mutex> lock(receive->completionMutex);
        if(!receive->completed) {
            Network::Socks5Udp::UnwrapResult decoded{};
            size_t copied=0;
            int error=0;
            if(internalBytes>receive->recvBuf.size() ||
               !DecodeUdpDatagram(receive->sock,receive->recvBuf.data(),internalBytes,
                   reinterpret_cast<sockaddr*>(&receive->fromTmp),receive->fromTmpLen,&decoded)) error=WSAECONNRESET;
            else {
                copied=CopyBytesToWsabufs(decoded.payload,decoded.payloadLen,receive->userBufs,receive->userBufCount);
                if(copied<decoded.payloadLen) error=WSAEMSGSIZE;
                if(receive->userFromLen) {
                    if(decoded.srcLen>0) {
                        if(!FillUserSockaddr(receive->userFrom,receive->userFromLen,decoded.src,decoded.srcLen)) error=WSAEFAULT;
                    } else *receive->userFromLen=0;
                }
            }
            receive->completedBytes=static_cast<DWORD>(copied); receive->completionError=error; receive->completed=true;
            ovl->InternalHigh=copied;
            if(error) ovl->Internal=static_cast<ULONG_PTR>(error==WSAEMSGSIZE?0x80000005u:0xC000020Du);
            std::vector<uint8_t>().swap(receive->recvBuf);
            std::vector<WSABUF>().swap(receive->userBuffers);
            receive->userBufs=nullptr; receive->userBufCount=0;
            receive->userFrom=nullptr; receive->userFromLen=nullptr;
        }
        result={receive->sock,receive->completedBytes,receive->completionError,receive->userCompletion};
    } else return false;
    // Do not hold a context mutex while acquiring the registry mutex: close and
    // cancellation walk the registry in the opposite direction.
    {
        std::lock_guard<std::mutex> lock(g_udpOvlMtx);
        auto sent=g_udpOvlSend.find(ovl);
        auto received=g_udpOvlRecv.find(ovl);
        bool owns=(send && sent!=g_udpOvlSend.end() && sent->second==send) ||
                  (receive && received!=g_udpOvlRecv.end() && received->second==receive);
        if(owns) {
            if(sent!=g_udpOvlSend.end()) g_udpOvlSend.erase(sent);
            if(received!=g_udpOvlRecv.end()) g_udpOvlRecv.erase(received);
            if(!consume) g_udpCompleted[ovl]=result;
        }
        if(consume) g_udpCompleted.erase(ovl);
    }
    if(outBytes) *outBytes=result.bytes;
    if(outError) *outError=result.error;
    return true;
}

static void CALLBACK UdpProxyCompletionRoutine(
    DWORD dwError,
    DWORD cbTransferred,
    LPWSAOVERLAPPED lpOverlapped,
    DWORD dwFlags
) {
    // 设计意图：在 CompletionRoutine 模式下，尽量把“解封装/bytes 修正”发生在用户回调之前。
    LPWSAOVERLAPPED_COMPLETION_ROUTINE userCb = nullptr;
    DWORD userBytes = cbTransferred;

    if (lpOverlapped) {
        // 先取出 user callback（因为 HandleUdpOverlappedCompletion 会 erase 上下文）
        {
            std::lock_guard<std::mutex> lock(g_udpOvlMtx);
            auto itS = g_udpOvlSend.find(lpOverlapped);
            if (itS != g_udpOvlSend.end() && itS->second) {
                userCb = itS->second->userCompletion;
            } else {
                auto itR = g_udpOvlRecv.find(lpOverlapped);
                if (itR != g_udpOvlRecv.end() && itR->second) {
                    userCb = itR->second->userCompletion;
                } else {
                    auto done=g_udpCompleted.find(lpOverlapped);
                    if(done!=g_udpCompleted.end()) userCb=done->second.callback;
                }
            }
        }

        if (dwError == 0) {
            int error=0;
            HandleUdpOverlappedCompletion(lpOverlapped, cbTransferred, &userBytes, &error, true);
            if(error) dwError=error;
        } else {
            // 失败：清理上下文，避免内存泄漏
            DropUdpOverlappedContext(lpOverlapped);
        }
    }

    if (userCb) {
        DropUdpOverlappedContext(lpOverlapped);
        userCb(dwError, userBytes, lpOverlapped, dwFlags);
    }
}

// 按指定地址族解析目标地址
static bool ResolveNameToAddrWithFamily(const std::string& node, const std::string& service, int family,
                                        sockaddr_storage* out, int* outLen, int* outErr) {
    if (!out || !outLen) return false;
    addrinfo hints{};
    hints.ai_family = family;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo* res = nullptr;
    const char* serviceStr = service.empty() ? nullptr : service.c_str();
    int rc = fpGetAddrInfo ? fpGetAddrInfo(node.c_str(), serviceStr, &hints, &res)
                           : getaddrinfo(node.c_str(), serviceStr, &hints, &res);
    if (outErr) *outErr = rc;
    if (rc != 0 || !res) {
        if (res) freeaddrinfo(res);
        return false;
    }
    if (res->ai_addrlen <= 0 || res->ai_addrlen > sizeof(sockaddr_storage)) {
        freeaddrinfo(res);
        if (outErr) *outErr = EAI_FAIL;
        return false;
    }
    memset(out, 0, sizeof(sockaddr_storage));
    memcpy(out, res->ai_addr, res->ai_addrlen);
    *outLen = (int)res->ai_addrlen;
    freeaddrinfo(res);
    return true;
}

// 解析目标域名为地址，供 WSAConnectByName 走代理（IPv6 允许时优先 IPv6）

static bool ResolveNameToAddr(SOCKET socket, const std::string& node, const std::string& service,
    const std::string&, sockaddr_storage* out, int* outLen) {
    if(!out || !outLen || node.empty()) return false;
    WSAPROTOCOL_INFOW info{}; int size=sizeof(info);
    if(getsockopt(socket,SOL_SOCKET,SO_PROTOCOL_INFOW,reinterpret_cast<char*>(&info),&size)!=0) return false;
    addrinfo hints{}; hints.ai_family=info.iAddressFamily; hints.ai_socktype=SOCK_STREAM;
    addrinfo* result=nullptr;
    int rc=getaddrinfo(node.c_str(),service.empty()?nullptr:service.c_str(),&hints,&result);
    if(rc || !result) { WSASetLastError(rc); return false; }
    bool valid=result->ai_addrlen<=sizeof(sockaddr_storage);
    if(valid) { memcpy(out,result->ai_addr,result->ai_addrlen); *outLen=static_cast<int>(result->ai_addrlen); }
    freeaddrinfo(result); return valid;
}

static bool TryResolveDirectTargetFromFakeIp(const sockaddr* name, const std::string& host, uint16_t port,
                                            sockaddr_storage* out, int* outLen, bool* outWasFakeIp) {
    if (outWasFakeIp) *outWasFakeIp = false;
    if (!name || !out || !outLen) return false;
    if (host.empty() || port == 0) return false;

    // 仅处理 FakeIP（IPv4 及 v4-mapped IPv6）
    bool isFake = false;
    const bool allow = Core::Config::Instance().fakeIp.enabled;
    if (!allow) return false;

    const int family = (int)name->sa_family;
    if (family == AF_INET) {
        const auto* a4 = (const sockaddr_in*)name;
        isFake = Network::FakeIP::Instance().IsFakeIP(a4->sin_addr.s_addr);
    } else if (family == AF_INET6) {
        const auto* a6 = (const sockaddr_in6*)name;
        if (IN6_IS_ADDR_V4MAPPED(&a6->sin6_addr)) {
            in_addr v4{};
            const unsigned char* raw = reinterpret_cast<const unsigned char*>(&a6->sin6_addr);
            memcpy(&v4, raw + 12, sizeof(v4));
            isFake = Network::FakeIP::Instance().IsFakeIP(v4.s_addr);
        }
    }

    if (!isFake) return false;
    if (outWasFakeIp) *outWasFakeIp = true;

    // 若 host 本身是 IP 字面量，重解析意义不大（也可能改变语义），这里直接交给上层回退。
    if (IsIpLiteralHost(host)) return false;

    const std::string service = std::to_string(port);
    int err = 0;

    // 优先按原始地址族重解析，保持与 socket family 兼容
    if (family == AF_INET) {
        return ResolveNameToAddrWithFamily(host, service, AF_INET, out, outLen, &err);
    }

    // v4-mapped IPv6：先尝试 IPv6（有 AAAA 时更准确）；失败则解析 IPv4 并转换为 v4-mapped IPv6
    if (family == AF_INET6) {
        if (ResolveNameToAddrWithFamily(host, service, AF_INET6, out, outLen, &err)) {
            return true;
        }

        sockaddr_storage v4{};
        int v4Len = 0;
        if (!ResolveNameToAddrWithFamily(host, service, AF_INET, &v4, &v4Len, &err)) {
            return false;
        }
        if (v4.ss_family != AF_INET) return false;

        const auto* a4 = (const sockaddr_in*)&v4;
        sockaddr_in6 mapped{};
        mapped.sin6_family = AF_INET6;
        mapped.sin6_port = htons(port);
        memset(&mapped.sin6_addr, 0, sizeof(mapped.sin6_addr));
        mapped.sin6_addr.u.Byte[10] = 0xff;
        mapped.sin6_addr.u.Byte[11] = 0xff;
        memcpy(&mapped.sin6_addr.u.Byte[12], &a4->sin_addr, sizeof(a4->sin_addr));

        memset(out, 0, sizeof(sockaddr_storage));
        memcpy(out, &mapped, sizeof(mapped));
        *outLen = (int)sizeof(mapped);
        return true;
    }

    return false;
}

// FakeIP 只在启用代理时分配：proxy.port=0（全部直连）时分配虚拟地址，后续直连会连到 198.18.x.x 而必然失败
static const sockaddr* ResolveDirectTarget(const sockaddr* name, int namelen, const std::string& host, uint16_t port,
                                           const char* reason, sockaddr_storage* storage, int* outLen) {
    *outLen = namelen;
    int realLen = 0;
    bool wasFake = false;
    if (TryResolveDirectTargetFromFakeIp(name, host, port, storage, &realLen, &wasFake)) {
        if (ShouldLogRouteDecisionInfo()) {
            const std::string dst = SockaddrToString((const sockaddr*)storage);
            Core::Logger::Info(std::string(reason) + ": FakeIP 已重解析直连" +
                               (dst.empty() ? std::string("") : (", addr=" + dst)) +
                               ", target=" + host + ":" + std::to_string(port));
        }
        *outLen = realLen;
        return (const sockaddr*)storage;
    }
    if (wasFake) {
        Core::Logger::Warn(std::string(reason) + ": 目标为 FakeIP 但重解析失败，回退原始直连(可能失败), target=" +
                           host + ":" + std::to_string(port));
    }
    return name;
}


static const sockaddr* ResolveUdpDirect(const sockaddr* address,int length,sockaddr_storage* storage,int* actualLength) {
    *actualLength=length;
    if(!address) return nullptr;
    std::string host; uint16_t port=0;
    if(!ResolveOriginalTarget(address,&host,&port)) return address;
    return ResolveDirectTarget(address,length,host,port,"UDP direct",storage,actualLength);
}
static int DirectUdpConnect(SOCKET s,const sockaddr* address,int length,bool wsa) {
    sockaddr_storage storage{}; int actualLength=length;
    auto actual=ResolveUdpDirect(address,length,&storage,&actualLength);
    return wsa?fpWSAConnect(s,actual,actualLength,nullptr,nullptr,nullptr,nullptr):fpConnect(s,actual,actualLength);
}
static BOOL DirectUdpConnectEx(SOCKET s,const sockaddr* address,int length,PVOID data,DWORD count,
    LPDWORD bytes,LPOVERLAPPED ovl,LPFN_CONNECTEX original) {
    sockaddr_storage storage{}; int actualLength=length;
    auto actual=ResolveUdpDirect(address,length,&storage,&actualLength);
    return original(s,actual,actualLength,data,count,bytes,ovl);
}
static int DirectUdpSendTo(SOCKET s,const char* data,int count,int flags,const sockaddr* address,int length) {
    sockaddr_storage storage{}; int actualLength=length;
    auto actual=ResolveUdpDirect(address,length,&storage,&actualLength);
    return fpSendTo(s,data,count,flags,actual,actualLength);
}
static int DirectUdpWSASendTo(SOCKET s,LPWSABUF buffers,DWORD count,LPDWORD bytes,DWORD flags,
    const sockaddr* address,int length,LPWSAOVERLAPPED ovl,LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) {
    sockaddr_storage storage{}; int actualLength=length;
    auto actual=ResolveUdpDirect(address,length,&storage,&actualLength);
    return fpWSASendTo(s,buffers,count,bytes,flags,actual,actualLength,ovl,completion);
}

static bool DoProxyHandshake(SOCKET s, const std::string& host, uint16_t port) {
    // FIX-2: 预检确保 socket 已成功连接到代理服务器，避免在未连接的 socket 上发送数据
    sockaddr_storage peerAddr{};
    int peerLen = sizeof(peerAddr);
    if (getpeername(s, (sockaddr*)&peerAddr, &peerLen) != 0) {
        int err = WSAGetLastError();
        Core::Logger::Error("代理握手: socket 未连接, sock=" + std::to_string((unsigned long long)s) +
                            ", 目标=" + host + ":" + std::to_string(port) +
                            ", WSA错误码=" + std::to_string(err));
        WSASetLastError(WSAENOTCONN);
        return false;
    }

    auto& config = Core::Config::Instance();
    // 握手预算采用 connect/send/recv 的总和，避免多阶段各自完整超时导致整体阻塞过长
    int handshakeBudgetMs = config.timeout.connect_ms + config.timeout.send_ms + config.timeout.recv_ms;
    if (handshakeBudgetMs <= 0) {
        handshakeBudgetMs = 5000;
    }
    if (Core::Logger::IsEnabled(Core::LogLevel::Debug)) {
        Core::Logger::Debug("代理握手: 开始, sock=" + std::to_string((unsigned long long)s) +
                            ", type=" + config.proxy.type +
                            ", 目标=" + host + ":" + std::to_string(port) +
                            ", 预算=" + std::to_string(handshakeBudgetMs) + "ms");
    }
    if (config.proxy.type == "socks5") {
        if (!Network::Socks5Client::Handshake(s, host, port, handshakeBudgetMs)) {
            Core::Logger::Error("SOCKS5 握手失败, sock=" + std::to_string((unsigned long long)s) +
                                ", 目标=" + host + ":" + std::to_string(port));
            WSASetLastError(WSAECONNREFUSED);
            return false;
        }
    } else if (config.proxy.type == "http") {
        if (!Network::HttpConnectClient::Handshake(s, host, port, handshakeBudgetMs)) {
            Core::Logger::Error("HTTP CONNECT 握手失败, sock=" + std::to_string((unsigned long long)s) +
                                ", 目标=" + host + ":" + std::to_string(port));
            WSASetLastError(WSAECONNREFUSED);
            return false;
        }
    } else {
        Core::Logger::Error("未知代理类型: " + config.proxy.type +
                            ", sock=" + std::to_string((unsigned long long)s) +
                            ", 目标=" + host + ":" + std::to_string(port));
        WSASetLastError(WSAECONNREFUSED);
        return false;
    }

    // 记录 socket -> 原始目标映射，便于在断开时输出可复盘日志
    RememberSocketTarget(s, host, port);
    
    // 隧道就绪日志：始终打印，便于排查问题（如"隧道建立成功但后续不通"）
    Core::Logger::Info("代理隧道就绪: sock=" + std::to_string((unsigned long long)s) +
                       ", type=" + config.proxy.type +
                       ", 代理=" + config.proxy.host + ":" + std::to_string(config.proxy.port) +
                       ", 目标=" + host + ":" + std::to_string(port));
    return true;
}

static void SaveConnectExContext(LPOVERLAPPED ovl, const ConnectExContext& ctx) {
    std::lock_guard<std::mutex> lock(g_connectExMtx);
    ULONGLONG now = GetTickCount64();
    ConnectExContext copy = ctx;
    copy.createdTick = now;
    g_connectExPending[ovl] = copy;
}

static bool FindConnectExContext(LPOVERLAPPED ovl, ConnectExContext* out) {
    std::lock_guard<std::mutex> lock(g_connectExMtx);
    auto it = g_connectExPending.find(ovl);
    if (it == g_connectExPending.end()) return false;
    if (out) *out = it->second;
    return true;
}

static void DropConnectExContext(LPOVERLAPPED ovl) {
    std::lock_guard<std::mutex> lock(g_connectExMtx);
    g_connectExPending.erase(ovl);
}

static void BeginOverlappedOperation(LPOVERLAPPED ovl) {
    if(!ovl) return;
    {
        std::lock_guard<std::mutex> lock(g_connectExMtx);
        auto it=g_connectExPending.find(ovl);
        if(it!=g_connectExPending.end()) {
            auto completion=it->second.completion;
            std::lock_guard<std::mutex> completionLock(completion->mutex);
            // Pending operations still own their state. Reuse is legal only
            // after completion has been observed by the application.
            if(it->second.completion->done) g_connectExPending.erase(it);
        }
    }
    std::lock_guard<std::mutex> lock(g_udpOvlMtx);
    g_udpCompleted.erase(ovl);
}

// 连接代理服务器失败时的排障提示（Issue #154）：
// 拒绝(10061)/超时(10060) 绝大多数是 proxy.port 与代理软件实际监听端口不一致或代理软件未启动；
// 此时应用侧报错常显示为“连接 198.18.x.x(FakeIP) 被拒绝”，容易被误判为 FakeIP 故障，因此在日志中直接给出核对方向。
static std::string BuildProxyConnectFailHint(int err) {
    if (err != WSAECONNREFUSED && err != WSAETIMEDOUT) return "";
    const auto& proxy = Core::Config::Instance().proxy;
    return "（提示：请核对 config.json 中 proxy.host:proxy.port=" + proxy.host + ":" + std::to_string(proxy.port) +
           " 是否与代理软件实际监听端口一致，并确认代理软件已启动）";
}

// ConnectEx 连接完成后更新上下文，避免 send 报 WSAENOTCONN
static bool UpdateConnectExContext(SOCKET s) {
    if (setsockopt(s, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0) != 0) {
        int err = WSAGetLastError();
        Core::Logger::Warn("ConnectEx: 更新连接上下文失败, sock=" + std::to_string((unsigned long long)s) +
                           ", WSA错误码=" + std::to_string(err));
    }
    int soErr = 0;
    int soErrLen = sizeof(soErr);
    if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&soErr, &soErrLen) == 0 && soErr != 0) {
        Core::Logger::Error("ConnectEx: 连接状态异常, sock=" + std::to_string((unsigned long long)s) +
                            ", SO_ERROR=" + std::to_string(soErr));
        WSASetLastError(soErr);
        return false;
    }
    return true;
}

static bool ExecuteConnectExCompletion(const ConnectExContext& ctx, DWORD* outSentBytes) {
    if (!UpdateConnectExContext(ctx.sock)) {
        return false;
    }

    // UDP ConnectEx：不做 TCP 握手，改为发送 SOCKS5 UDP 封装数据
    if (ctx.isUdp) {
        MarkUdpRelayConnected(ctx.sock);
        UpdateUdpProxyDefaultTarget(ctx.sock, ctx.host, ctx.port);
        RememberSocketTarget(ctx.sock, ctx.host, ctx.port);

        if (ctx.sendBuf && ctx.sendLen > 0) {
            std::vector<uint8_t> packet;
            if (!Network::Socks5Udp::Wrap(ctx.host, ctx.port, (const uint8_t*)ctx.sendBuf, (size_t)ctx.sendLen, &packet)) {
                WSASetLastError(WSAECONNREFUSED);
                return false;
            }
            auto& config = Core::Config::Instance();
            if (!SendUdpPacketWithRetry(ctx.sock, packet.data(), (int)packet.size(), 0, config.timeout.send_ms)) {
                int err = WSAGetLastError();
                Core::Logger::Error("ConnectEx(UDP) 发送首包失败, sock=" + std::to_string((unsigned long long)ctx.sock) +
                                    ", bytes=" + std::to_string((unsigned long long)ctx.sendLen) +
                                    ", WSA错误码=" + std::to_string(err));
                WSASetLastError(err);
                return false;
            }
            if (outSentBytes) {
                *outSentBytes = (DWORD)ctx.sendLen;
            }
        }
        return true;
    }

    // TCP ConnectEx：保持原逻辑（先握手，再可选发送首包）
    if (!DoProxyHandshake(ctx.sock, ctx.host, ctx.port)) {
        return false;
    }
    if (ctx.sendBuf && ctx.sendLen > 0) {
        // 使用统一 SendAll，兼容非阻塞 socket / partial send
        auto& config = Core::Config::Instance();
        if (!Network::SocketIo::SendAll(ctx.sock, ctx.sendBuf, (int)ctx.sendLen, config.timeout.send_ms)) {
            int err = WSAGetLastError();
            Core::Logger::Error("ConnectEx 发送首包失败, sock=" + std::to_string((unsigned long long)ctx.sock) +
                                ", bytes=" + std::to_string((unsigned long long)ctx.sendLen) +
                                ", WSA错误码=" + std::to_string(err));
            WSASetLastError(err);
            return false;
        }
        if (outSentBytes) {
            *outSentBytes = (DWORD)ctx.sendLen;
        }
    }
    return true;
}


static bool HandleConnectExCompletion(LPOVERLAPPED ovl, DWORD* outSentBytes) {
    if (outSentBytes) *outSentBytes = 0;
    ConnectExContext ctx{};
    if (!FindConnectExContext(ovl, &ctx)) return true;
    std::lock_guard<std::mutex> lock(ctx.completion->mutex);
    auto& completion = *ctx.completion;
    if (!completion.done) {
        completion.success = ExecuteConnectExCompletion(ctx, &completion.bytes);
        completion.error = completion.success ? 0 : WSAGetLastError();
        if (!completion.success) {
            ovl->Internal = static_cast<ULONG_PTR>(0xC0000236u); // STATUS_CONNECTION_REFUSED
            fpShutdown(ctx.sock, SD_BOTH);
        }
        ovl->InternalHigh = completion.bytes;
        completion.done = true;
    }
    if (outSentBytes) *outSentBytes = completion.bytes;
    if (!completion.success) WSASetLastError(completion.error ? completion.error : WSAECONNREFUSED);
    return completion.success;
}

BOOL PASCAL DetourConnectEx(
    SOCKET s,
    const struct sockaddr* name,
    int namelen,
    PVOID lpSendBuffer,
    DWORD dwSendDataLength,
    LPDWORD lpdwBytesSent,
    LPOVERLAPPED lpOverlapped
);

// ============= UDP 代理连接逻辑（用于 QUIC/HTTP3 等 UDP 协议） =============

static bool IsBlockedUdpV6(const sockaddr* address) {
    const auto& config=Core::Config::Instance();
    return config.proxy.port>0 && config.rules.ipv6_mode=="block" && address &&
        address->sa_family==AF_INET6 &&
        !IN6_IS_ADDR_V4MAPPED(&reinterpret_cast<const sockaddr_in6*>(address)->sin6_addr) &&
        !IsSockaddrLoopback(address);
}

static bool ShouldProxyUdpByRule(const sockaddr* name, const std::string& originalHost, uint16_t originalPort) {
    auto& config = Core::Config::Instance();
    if (config.proxy.port == 0) return false;
    if (GetEffectiveUdpAction(config) != Core::UdpAction::Proxy) return false;

    // loopback 永远直连（避免递归与本地调试端口被误伤）
    if (IsSockaddrLoopback(name) || IsLoopbackHost(originalHost)) return false;

    // DNS 特殊处理：dns_mode=direct 时不代理 UDP 53
    if (originalPort == 53 && (config.rules.dns_mode == "direct" || config.rules.dns_mode.empty())) {
        return false;
    }

    // 端口白名单：不在白名单则不代理
    if (!(originalPort == 53 && config.rules.dns_mode == "proxy") && !config.rules.IsPortAllowed(originalPort)) return false;

    // IPv6 策略：纯 IPv6 连接先按 ipv6_mode 处理（与 TCP 路径保持一致）
    if (name && name->sa_family == AF_INET6) {
        const auto* a6 = (const sockaddr_in6*)name;
        const bool isV4Mapped = IN6_IS_ADDR_V4MAPPED(&a6->sin6_addr);
        if (!isV4Mapped) {
            if (config.rules.ipv6_mode == "direct") return false;
            if (config.rules.ipv6_mode == "block") return false;
        }
    }

    // 路由规则：支持 protocols=["udp"] 做分流（不命中则走默认 action）
    std::string addrIp;
    bool addrIsV6 = false;
    SockaddrToIp(name, &addrIp, &addrIsV6);
    std::string routeAction;
    std::string routeRule;
    config.rules.MatchRouting(originalHost, addrIp, addrIsV6, originalPort, "udp", &routeAction, &routeRule);
    routeAction = Core::ProxyRules::ToLower(std::move(routeAction));
    if (routeAction == "direct") {
        if (Core::Logger::IsEnabled(Core::LogLevel::Debug)) {
            Core::Logger::Debug("[Route] UDP direct, rule=" + (routeRule.empty() ? std::string("(default)") : routeRule) +
                                ", target=" + originalHost + ":" + std::to_string(originalPort));
        }
        return false;
    }

    return true;
}

static int PerformProxyUdpConnect(SOCKET s, const sockaddr* name, int namelen, bool isWsa) {
    auto& config = Core::Config::Instance();

    std::string originalHost;
    uint16_t originalPort = 0;
    if (!ResolveOriginalTarget(name, &originalHost, &originalPort)) {
        return DirectUdpConnect(s,name,namelen,isWsa);
    }

    // 保存“逻辑目标”，便于日志/后续 send(UDP) 封装
    g_currentTarget.host = originalHost;
    g_currentTarget.port = originalPort;

    // direct 路径（含路由/策略）
    if (IsBlockedUdpV6(name)) { WSASetLastError(WSAEACCES); return SOCKET_ERROR; }
    if (!ShouldProxyUdpByRule(name, originalHost, originalPort)) {
        if (Core::Logger::IsEnabled(Core::LogLevel::Debug)) {
            Core::Logger::Debug(std::string(isWsa ? "WSAConnect" : "connect") +
                                ": UDP 直连, sock=" + std::to_string((unsigned long long)s) +
                                ", target=" + originalHost + ":" + std::to_string(originalPort));
        }
        return DirectUdpConnect(s,name,namelen,isWsa);
    }

    // block IPv6（如果策略要求）
    if (name && name->sa_family == AF_INET6) {
        const auto* a6 = (const sockaddr_in6*)name;
        const bool isV4Mapped = IN6_IS_ADDR_V4MAPPED(&a6->sin6_addr);
        if (!isV4Mapped && config.rules.ipv6_mode == "block") {
            const int err = WSAEACCES;
            Core::Logger::Warn("UDP IPv6 已阻止(策略: ipv6_mode=block), sock=" + std::to_string((unsigned long long)s) +
                               ", target=" + originalHost + ":" + std::to_string(originalPort) +
                               ", WSA错误码=" + std::to_string(err));
            WSASetLastError(err);
            return SOCKET_ERROR;
        }
    }

    // 确保 UDP Associate 就绪，并将本 socket connect 到 relay
    if (!EnsureUdpProxyReady(s, name->sa_family, originalHost, originalPort, true)) {
        // 失败降级：按配置回退 direct 或维持失败(block)
        if (config.rules.udp_fallback == "direct") {
            if (ShouldLogUdpProxyFail()) {
                const int err = WSAGetLastError();
                Core::Logger::Warn("UDP 代理失败，回退为 direct, sock=" + std::to_string((unsigned long long)s) +
                                   ", target=" + originalHost + ":" + std::to_string(originalPort) +
                                   ", WSA错误码=" + std::to_string(err));
            }
            CleanupUdpProxyContext(s);
            return DirectUdpConnect(s,name,namelen,isWsa);
        }
        return SOCKET_ERROR;
    }

    RememberSocketTarget(s, originalHost, originalPort);
    if (Core::Logger::IsEnabled(Core::LogLevel::Debug)) {
        Core::Logger::Debug(std::string(isWsa ? "WSAConnect" : "connect") +
                            ": UDP 已重定向到 SOCKS5 relay, sock=" + std::to_string((unsigned long long)s) +
                            ", target=" + originalHost + ":" + std::to_string(originalPort));
    }
    return 0;
}

static BOOL PerformProxyUdpConnectEx(
    SOCKET s,
    const sockaddr* name,
    int namelen,
    PVOID lpSendBuffer,
    DWORD dwSendDataLength,
    LPDWORD lpdwBytesSent,
    LPOVERLAPPED lpOverlapped,
    LPFN_CONNECTEX originalConnectEx
) {
    if (!originalConnectEx) {
        WSASetLastError(WSAEINVAL);
        return FALSE;
    }

    auto& config = Core::Config::Instance();

    std::string originalHost;
    uint16_t originalPort = 0;
    if (!ResolveOriginalTarget(name, &originalHost, &originalPort)) {
        return DirectUdpConnectEx(s,name,namelen,lpSendBuffer,dwSendDataLength,lpdwBytesSent,lpOverlapped,originalConnectEx);
    }

    // 保存“逻辑目标”，便于后续首包发送封装
    g_currentTarget.host = originalHost;
    g_currentTarget.port = originalPort;

    if (IsBlockedUdpV6(name)) { WSASetLastError(WSAEACCES); return FALSE; }
    if (!ShouldProxyUdpByRule(name, originalHost, originalPort)) {
        return DirectUdpConnectEx(s,name,namelen,lpSendBuffer,dwSendDataLength,lpdwBytesSent,lpOverlapped,originalConnectEx);
    }

    if (name && name->sa_family == AF_INET6) {
        const auto* a6 = (const sockaddr_in6*)name;
        const bool isV4Mapped = IN6_IS_ADDR_V4MAPPED(&a6->sin6_addr);
        if (!isV4Mapped && config.rules.ipv6_mode == "block") {
            const int err = WSAEACCES;
            Core::Logger::Warn("ConnectEx(UDP) IPv6 已阻止(策略: ipv6_mode=block), sock=" + std::to_string((unsigned long long)s) +
                               ", target=" + originalHost + ":" + std::to_string(originalPort) +
                               ", WSA错误码=" + std::to_string(err));
            WSASetLastError(err);
            return FALSE;
        }
    }

    // 确保已获取 relay（但 connect 由 originalConnectEx 完成，以保持 Overlapped 语义）
    if (!EnsureUdpProxyReady(s, name->sa_family, originalHost, originalPort, false)) {
        if (config.rules.udp_fallback == "direct") {
            if (ShouldLogUdpProxyFail()) {
                const int err = WSAGetLastError();
                Core::Logger::Warn("ConnectEx(UDP) 代理准备失败，回退为 direct, sock=" + std::to_string((unsigned long long)s) +
                                   ", target=" + originalHost + ":" + std::to_string(originalPort) +
                                   ", WSA错误码=" + std::to_string(err));
            }
            CleanupUdpProxyContext(s);
            return DirectUdpConnectEx(s,name,namelen,lpSendBuffer,dwSendDataLength,lpdwBytesSent,lpOverlapped,originalConnectEx);
        }
        return FALSE;
    }

    sockaddr_storage relay{};
    int relayLen = 0;
    if (!TryGetUdpRelayAddr(s, &relay, &relayLen)) {
        WSASetLastError(WSAECONNREFUSED);
        if (config.rules.udp_fallback == "direct") {
            if (ShouldLogUdpProxyFail()) {
                Core::Logger::Warn("ConnectEx(UDP) 获取 relay 失败，回退为 direct, sock=" + std::to_string((unsigned long long)s) +
                                   ", target=" + originalHost + ":" + std::to_string(originalPort));
            }
            CleanupUdpProxyContext(s);
            return DirectUdpConnectEx(s,name,namelen,lpSendBuffer,dwSendDataLength,lpdwBytesSent,lpOverlapped,originalConnectEx);
        }
        return FALSE;
    }

    sockaddr_storage relayForSock{};
    int relayForSockLen = 0;
    if (!BuildUdpRelayAddrForSocketFamily(name->sa_family, relay, relayLen, &relayForSock, &relayForSockLen)) {
        WSASetLastError(WSAEAFNOSUPPORT);
        if (config.rules.udp_fallback == "direct") {
            if (ShouldLogUdpProxyFail()) {
                Core::Logger::Warn("ConnectEx(UDP) relay 地址族不兼容，回退为 direct, sock=" + std::to_string((unsigned long long)s) +
                                   ", target=" + originalHost + ":" + std::to_string(originalPort));
            }
            CleanupUdpProxyContext(s);
            return DirectUdpConnectEx(s,name,namelen,lpSendBuffer,dwSendDataLength,lpdwBytesSent,lpOverlapped,originalConnectEx);
        }
        return FALSE;
    }
    if (relayForSock.ss_family == AF_INET6 &&
        !PrepareIpv4MappedProxyDestination(
            s,
            *reinterpret_cast<const sockaddr_in6*>(&relayForSock))) {
        if (config.rules.udp_fallback == "direct") {
            CleanupUdpProxyContext(s);
            return originalConnectEx(
                s, name, namelen, lpSendBuffer, dwSendDataLength,
                lpdwBytesSent, lpOverlapped);
        }
        return FALSE;
    }

    // 注意：不能把原始 lpSendBuffer 透传给 ConnectEx，否则应用会把“未封装的 UDP payload”发给 relay

    if (!lpOverlapped) { WSASetLastError(WSAEINVAL); return FALSE; }
    ConnectExContext ctx{};
    ctx.sock=s; ctx.host=originalHost; ctx.port=originalPort;
    ctx.sendBuf=static_cast<const char*>(lpSendBuffer); ctx.sendLen=dwSendDataLength; ctx.isUdp=true;
    SaveConnectExContext(lpOverlapped,ctx);
    BOOL result=originalConnectEx(s,reinterpret_cast<sockaddr*>(&relayForSock),relayForSockLen,
                                 nullptr,0,nullptr,lpOverlapped);
    if (!result) {
        int error=WSAGetLastError();
        if (error!=WSA_IO_PENDING) DropConnectExContext(lpOverlapped);
        WSASetLastError(error); return FALSE;
    }
    DWORD sent=0;
    if (!HandleConnectExCompletion(lpOverlapped,&sent)) return FALSE;
    if (lpdwBytesSent) *lpdwBytesSent=sent;
    return TRUE;
}

// 执行代理连接逻辑
int PerformProxyConnect(SOCKET s, const struct sockaddr* name, int namelen, bool isWsa) {
    auto& config = Core::Config::Instance();
    LogRuntimeConfigSummaryOnce();
    
    // 超时控制
    Network::SocketWrapper sock(s);
    sock.SetTimeouts(config.timeout.recv_ms, config.timeout.send_ms);
    
    // 基础参数校验，避免空指针/长度不足导致崩溃
    if (!name) {
        WSASetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }
    if (namelen < (int)sizeof(sockaddr)) {
        WSASetLastError(WSAEINVAL);
        return SOCKET_ERROR;
    }
    if (name->sa_family == AF_INET && namelen < (int)sizeof(sockaddr_in)) {
        WSASetLastError(WSAEINVAL);
        return SOCKET_ERROR;
    }
    if (name->sa_family == AF_INET6 && namelen < (int)sizeof(sockaddr_in6)) {
        WSASetLastError(WSAEINVAL);
        return SOCKET_ERROR;
    }

    // Hook 调用日志：仅在 Debug 下记录参数，避免热路径字符串拼接开销
    if (Core::Logger::IsEnabled(Core::LogLevel::Debug)) {
        const std::string dst = SockaddrToString(name);
        Core::Logger::Debug(std::string(isWsa ? "WSAConnect" : "connect") +
                            ": 调用, sock=" + std::to_string((unsigned long long)s) +
                            ", dst=" + (dst.empty() ? "(未知)" : dst) +
                            ", family=" + std::to_string((int)name->sa_family) +
                            ", namelen=" + std::to_string(namelen));
    }
    
    // 仅对 TCP (SOCK_STREAM) 做代理，避免误伤 UDP/QUIC 等
    if (config.proxy.port != 0) {
        const int soType = GetSocketTypeForProxyDecision(s);
        if (soType != SOCK_STREAM) {

            if (soType == SOCK_DGRAM) {
                // 有效策略为 block 时阻断 UDP（DNS/loopback 例外），促使应用回退到 TCP。
                if (IsBlockedUdpV6(name)) { WSASetLastError(WSAEACCES); return SOCKET_ERROR; }
            const Core::UdpAction udpAction = GetEffectiveUdpAction(config);
                if (udpAction == Core::UdpAction::Block) {
                    uint16_t dstPort = 0;
                    const bool hasPort = TryGetSockaddrPort(name, &dstPort);
                    // 例外判断统一收敛到 IsUdpBlockExempt（loopback / UDP53 / 局域网等 direct 路由规则）
                    const bool allowUdp = IsUdpBlockExempt(config, name, hasPort, dstPort);
                    if (!allowUdp) {
                        const int err = WSAEACCES;
                        if (ShouldLogUdpBlock()) {
                            const std::string api = isWsa ? "WSAConnect" : "connect";
                            const std::string dst = SockaddrToString(name);
                            Core::Logger::Warn(api + ": 已阻止 UDP 连接(策略: " + GetUdpPolicyLabel(config) + "), sock=" + std::to_string((unsigned long long)s) +
                                               (dst.empty() ? "" : ", dst=" + dst) +
                                               (hasPort ? (", port=" + std::to_string(dstPort)) : std::string("")) +
                                               ", WSA错误码=" + std::to_string(err));
                        }
                        WSASetLastError(err);
                        return SOCKET_ERROR;
                    }
                    if (Core::Logger::IsEnabled(Core::LogLevel::Debug)) {
                        const std::string dst = SockaddrToString(name);
                        Core::Logger::Debug(std::string(isWsa ? "WSAConnect" : "connect") +
                                            ": UDP 直连已放行(例外), sock=" + std::to_string((unsigned long long)s) +
                                            (dst.empty() ? "" : ", dst=" + dst));
                    }
                    return isWsa ? fpWSAConnect(s, name, namelen, NULL, NULL, NULL, NULL) : fpConnect(s, name, namelen);
                }

                // UDP 走代理：用于 QUIC/HTTP3（通过 SOCKS5 UDP Associate）
                if (udpAction == Core::UdpAction::Proxy) {
                    return PerformProxyUdpConnect(s, name, namelen, isWsa);
                }

                // 有效策略为 direct：保持直连
                return DirectUdpConnect(s,name,namelen,isWsa);
            }

            // 其他非 SOCK_STREAM 类型保持直连；仅在 Debug 下记录，避免刷屏影响性能
            if (Core::Logger::IsEnabled(Core::LogLevel::Debug)) {
                const std::string dst = SockaddrToString(name);
                Core::Logger::Debug(std::string(isWsa ? "WSAConnect" : "connect") +
                                    ": 非 SOCK_STREAM 直连, sock=" + std::to_string((unsigned long long)s) +
                                    ", soType=" + std::to_string(soType) +
                                    (dst.empty() ? "" : ", dst=" + dst));
            }
            return isWsa ? fpWSAConnect(s, name, namelen, NULL, NULL, NULL, NULL) : fpConnect(s, name, namelen);
        }
    }

    if (name->sa_family == AF_INET6) {
        const auto* addr6 = (const sockaddr_in6*)name;
        const bool isV4Mapped = IN6_IS_ADDR_V4MAPPED(&addr6->sin6_addr);

        // v4-mapped IPv6 本质是 IPv4 连接：不应被 ipv6_mode 误伤（否则会影响 FakeIP v4-mapped 回填）
        if (!isV4Mapped) {
            // WARN-5: 优先级说明：纯 IPv6 连接会先按 ipv6_mode 决策（direct/block/proxy），
            // 仅当 ipv6_mode=proxy 时才会继续进入下方的 routing 规则匹配。
            std::string addrStr = SockaddrToString(name);
            if (config.proxy.port != 0) {
                const std::string& ipv6Mode = config.rules.ipv6_mode;
                if (ipv6Mode == "direct") {
                    Core::Logger::Info("IPv6 连接已直连(策略: direct), sock=" + std::to_string((unsigned long long)s) +
                                       ", family=" + std::to_string((int)name->sa_family) +
                                       (addrStr.empty() ? "" : ", addr=" + addrStr));
                    return isWsa ? fpWSAConnect(s, name, namelen, NULL, NULL, NULL, NULL) : fpConnect(s, name, namelen);
                }
                if (ipv6Mode != "proxy") {
                    // 强制阻止 IPv6，避免绕过代理
                    Core::Logger::Warn("已阻止 IPv6 连接(策略: block), sock=" + std::to_string((unsigned long long)s) +
                                       ", family=" + std::to_string((int)name->sa_family) +
                                       (addrStr.empty() ? "" : ", addr=" + addrStr));
                    WSASetLastError(WSAEAFNOSUPPORT);
                    return SOCKET_ERROR;
                }
            } else {
                Core::Logger::Info("IPv6 连接已直连, sock=" + std::to_string((unsigned long long)s) +
                                   ", family=" + std::to_string((int)name->sa_family) +
                                   (addrStr.empty() ? "" : ", addr=" + addrStr));
                return DirectUdpConnect(s,name,namelen,isWsa);
            }
        }
    } else if (name->sa_family != AF_INET) {
        std::string addrStr = SockaddrToString(name);
        if (config.proxy.port != 0) {
            // 非 IPv4/IPv6 连接一律阻止，避免绕过代理
            Core::Logger::Warn("已阻止非 IPv4/IPv6 连接, sock=" + std::to_string((unsigned long long)s) +
                               ", family=" + std::to_string((int)name->sa_family) +
                               (addrStr.empty() ? "" : ", addr=" + addrStr));
            WSASetLastError(WSAEAFNOSUPPORT);
            return SOCKET_ERROR;
        }
        Core::Logger::Info("非 IPv4/IPv6 连接已直连, sock=" + std::to_string((unsigned long long)s) +
                           ", family=" + std::to_string((int)name->sa_family) +
                           (addrStr.empty() ? "" : ", addr=" + addrStr));
        return isWsa ? fpWSAConnect(s, name, namelen, NULL, NULL, NULL, NULL) : fpConnect(s, name, namelen);
    }
    
    std::string originalHost;
    uint16_t originalPort = 0;
    if (!ResolveOriginalTarget(name, &originalHost, &originalPort)) {
        return isWsa ? fpWSAConnect(s, name, namelen, NULL, NULL, NULL, NULL) : fpConnect(s, name, namelen);
    }
    
    // 保存原始目标
    g_currentTarget.host = originalHost;
    g_currentTarget.port = originalPort;
    
    // BYPASS: 跳过本地回环地址，避免代理死循环
    if (IsLoopbackHost(originalHost)) {
        if (Core::Logger::IsEnabled(Core::LogLevel::Debug)) {
            Core::Logger::Debug("BYPASS(loopback): sock=" + std::to_string((unsigned long long)s) +
                                ", target=" + originalHost + ":" + std::to_string(originalPort));
        }
        return isWsa ? fpWSAConnect(s, name, namelen, NULL, NULL, NULL, NULL) : fpConnect(s, name, namelen);
    }
    
    // BYPASS: 如果目标端口就是代理端口，直连（防止代理自连接）
    if (IsProxySelfTarget(originalHost, originalPort, config.proxy)) {
        if (Core::Logger::IsEnabled(Core::LogLevel::Debug)) {
            Core::Logger::Debug("BYPASS(proxy-self): sock=" + std::to_string((unsigned long long)s) +
                                ", target=" + originalHost + ":" + std::to_string(originalPort) +
                                ", proxy=" + config.proxy.host + ":" + std::to_string(config.proxy.port));
        }
        return isWsa ? fpWSAConnect(s, name, namelen, NULL, NULL, NULL, NULL) : fpConnect(s, name, namelen);
    }

    // ROUTE-0: 自定义路由规则（域名/CIDR/端口/协议）
    std::string addrIp;
    bool addrIsV6 = false;
    SockaddrToIp(name, &addrIp, &addrIsV6);
    std::string routeAction;
    std::string routeRule;
    const bool routeMatched = config.rules.MatchRouting(originalHost, addrIp, addrIsV6, originalPort, "tcp",
                                                        &routeAction, &routeRule);
    if (!routeAction.empty() && routeAction == "direct") {
        if (ShouldLogRouteDecisionInfo()) {
            Core::Logger::Info("[Route] direct" +
                               std::string(routeMatched ? (" rule=" + routeRule) : " rule=(default)") +
                               ", target=" + originalHost + ":" + std::to_string(originalPort));
        }
        // CRIT-3: 若底层 sockaddr 仍为 FakeIP，则 direct 直连必失败；这里做兜底重解析
        sockaddr_storage directAddr{};
        int directLen = 0;
        const sockaddr* direct = ResolveDirectTarget(name, namelen, originalHost, originalPort, "[Route] direct",
                                                     &directAddr, &directLen);
        return isWsa ? fpWSAConnect(s, direct, directLen, NULL, NULL, NULL, NULL)
                     : fpConnect(s, direct, directLen);
    } else if (routeMatched) {
        if (ShouldLogRouteDecisionInfo()) {
            Core::Logger::Info("[Route] proxy rule=" + routeRule +
                               ", target=" + originalHost + ":" + std::to_string(originalPort));
        }
    }
    
    // ============= 智能路由决策 =============
    // ROUTE-1: DNS 端口特殊处理 (解决 DNS 超时问题)
    if (originalPort == 53) {
        if (config.rules.dns_mode == "direct" || config.rules.dns_mode.empty()) {
            if (ShouldLogRouteDecisionInfo()) {
                Core::Logger::Info("DNS 请求直连 (策略: direct), sock=" + std::to_string((unsigned long long)s) +
                                   ", 目标: " + originalHost + ":53");
            }
            // 以域名指定的 DNS 服务器（如 dns.google:53）同样拿到的是 FakeIP，直连前需还原
            sockaddr_storage directAddr{};
            int directLen = 0;
            const sockaddr* direct = ResolveDirectTarget(name, namelen, originalHost, originalPort, "DNS 直连",
                                                         &directAddr, &directLen);
            return isWsa ? fpWSAConnect(s, direct, directLen, NULL, NULL, NULL, NULL)
                         : fpConnect(s, direct, directLen);
        }
        // dns_mode == "proxy" 则继续走后面的代理逻辑
        if (ShouldLogRouteDecisionInfo()) {
            Core::Logger::Info("DNS 请求走代理 (策略: proxy), sock=" + std::to_string((unsigned long long)s) +
                               ", 目标: " + originalHost + ":53");
        }
    }
    
    // ROUTE-2: 端口白名单过滤
    if (!(originalPort == 53 && config.rules.dns_mode == "proxy") && !config.rules.IsPortAllowed(originalPort)) {
        if (ShouldLogRouteDecisionInfo()) {
            Core::Logger::Info("端口 " + std::to_string(originalPort) + " 不在白名单, sock=" + std::to_string((unsigned long long)s) +
                               ", 直连: " + originalHost);
        }
        // 域名连接（如 node 扩展宿主连 MCP 服务 / 数据库的 8080、5432 端口）此时持有的是 FakeIP，直连前需还原
        sockaddr_storage directAddr{};
        int directLen = 0;
        const sockaddr* direct = ResolveDirectTarget(name, namelen, originalHost, originalPort, "端口白名单外直连",
                                                     &directAddr, &directLen);
        return isWsa ? fpWSAConnect(s, direct, directLen, NULL, NULL, NULL, NULL)
                     : fpConnect(s, direct, directLen);
    }
    
    // 如果配置了代理
    if (config.proxy.port != 0) {
        if (ShouldLogRouteDecisionInfo()) {
            Core::Logger::Info("正重定向 " + originalHost + ":" + std::to_string(originalPort) +
                               " 到代理, sock=" + std::to_string((unsigned long long)s));
        }
        
        // 修改目标地址为代理服务器（按地址族构造）
        int result = 0;
        if (name->sa_family == AF_INET6) {
            sockaddr_in6 proxyAddr6{};
            if (!BuildProxyAddrV6(config.proxy, &proxyAddr6, (sockaddr_in6*)name)) {
                WSASetLastError(WSAEINVAL);
                return SOCKET_ERROR;
            }
            if (!PrepareIpv4MappedProxyDestination(s, proxyAddr6)) {
                return SOCKET_ERROR;
            }
            result = ConnectProxyWithDeadline(s, reinterpret_cast<sockaddr*>(&proxyAddr6), sizeof(proxyAddr6), isWsa);
        } else {
            sockaddr_in proxyAddr{};
            if (!BuildProxyAddr(config.proxy, &proxyAddr, (sockaddr_in*)name)) {
                WSASetLastError(WSAEINVAL);
                return SOCKET_ERROR;
            }
            result = ConnectProxyWithDeadline(s, reinterpret_cast<sockaddr*>(&proxyAddr), sizeof(proxyAddr), isWsa);
        }
        
        if (result != 0) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK || err == WSAEINPROGRESS) {
                // 非阻塞 connect 需要等待连接完成
                if (!Network::SocketIo::WaitConnect(s, config.timeout.connect_ms)) {
                    int waitErr = WSAGetLastError();
                    Core::Logger::Error("连接代理服务器失败, sock=" + std::to_string((unsigned long long)s) +
                                        ", WSA错误码=" + std::to_string(waitErr) +
                                        BuildProxyConnectFailHint(waitErr));
                    return SOCKET_ERROR;
                }
            } else {
                Core::Logger::Error("连接代理服务器失败, sock=" + std::to_string((unsigned long long)s) +
                                    ", WSA错误码=" + std::to_string(err) +
                                    BuildProxyConnectFailHint(err));
                return result;
            }
        }
        
        if (!DoProxyHandshake(s, originalHost, originalPort)) {
            int error = WSAGetLastError(); fpShutdown(s, SD_BOTH); WSASetLastError(error);
            return SOCKET_ERROR;
        }
        
        return 0; // 成功
    }
    
    // 无代理配置，直接连接
    return isWsa ? fpWSAConnect(s, name, namelen, NULL, NULL, NULL, NULL) : fpConnect(s, name, namelen);
}

// ============= Phase 1: 网络 Hook 函数实现 =============

SOCKET WSAAPI DetourSocket(int addressFamily, int type, int protocol) {
    const SOCKET socket = fpSocket(addressFamily, type, protocol);
    RememberSocketMode(socket, false);
    ConfigureCreatedSocketForProxy(socket, addressFamily, "socket");
    return socket;
}

SOCKET WSAAPI DetourWSASocketA(
    int addressFamily,
    int type,
    int protocol,
    LPWSAPROTOCOL_INFOA protocolInfo,
    GROUP group,
    DWORD flags) {
    const SOCKET socket = fpWSASocketA(addressFamily, type, protocol, protocolInfo, group, flags);
    RememberSocketMode(socket, false);
    ConfigureCreatedSocketForProxy(socket, addressFamily, "WSASocketA");
    return socket;
}

SOCKET WSAAPI DetourWSASocketW(
    int addressFamily,
    int type,
    int protocol,
    LPWSAPROTOCOL_INFOW protocolInfo,
    GROUP group,
    DWORD flags) {
    const SOCKET socket = fpWSASocketW(addressFamily, type, protocol, protocolInfo, group, flags);
    RememberSocketMode(socket, false);
    ConfigureCreatedSocketForProxy(socket, addressFamily, "WSASocketW");
    return socket;
}

int WSAAPI DetourConnect(SOCKET s, const struct sockaddr* name, int namelen) {
    if (Network::IsLocalSockaddr(name, namelen)) {
        CleanupUdpProxyContext(s);
        ForgetSocketTarget(s);
        const int result = fpConnect(s, name, namelen);
        const int error = result == SOCKET_ERROR ? WSAGetLastError() : 0;
        UpdateLocalBypassSocketAfterConnect(s, result == 0, error);
        LogLocalTargetBypass("connect", s, SockaddrToString(name));
        if (result == SOCKET_ERROR) WSASetLastError(error);
        return result;
    }
    SetLocalBypassSocket(s, false);
    return PerformProxyConnect(s, name, namelen, false);
}

int WSAAPI DetourWSAConnect(SOCKET s, const struct sockaddr* name, int namelen, 
                            LPWSABUF lpCallerData, LPWSABUF lpCalleeData, 
                            LPQOS lpSQOS, LPQOS lpGQOS) {
    if (Network::IsLocalSockaddr(name, namelen)) {
        CleanupUdpProxyContext(s);
        ForgetSocketTarget(s);
        const int result = fpWSAConnect(
            s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
        const int error = result == SOCKET_ERROR ? WSAGetLastError() : 0;
        UpdateLocalBypassSocketAfterConnect(s, result == 0, error);
        LogLocalTargetBypass("WSAConnect", s, SockaddrToString(name));
        if (result == SOCKET_ERROR) WSASetLastError(error);
        return result;
    }
    SetLocalBypassSocket(s, false);
    // 外部目标沿用现有统一代理逻辑。
    return PerformProxyConnect(s, name, namelen, true);
}

int WSAAPI DetourShutdown(SOCKET s, int how) {
    if (!fpShutdown) {
        WSASetLastError(WSAEINVAL);
        return SOCKET_ERROR;
    }

    if (IsLocalBypassSocket(s)) {
        return fpShutdown(s, how);
    }

    SocketTargetInfo target{};
    const bool hasTarget = TryGetSocketTarget(s, &target);

    if (Core::Logger::IsEnabled(Core::LogLevel::Debug)) {
        const std::string local = GetLocalEndpoint(s);
        const std::string peer = GetPeerEndpoint(s);
        const std::string targetStr = hasTarget
            ? (target.host + ":" + std::to_string(target.port))
            : std::string("(未知)");
        Core::Logger::Debug("shutdown: sock=" + std::to_string((unsigned long long)s) +
                            ", how=" + std::to_string(how) +
                            ", target=" + targetStr +
                            (local.empty() ? "" : ", local=" + local) +
                            (peer.empty() ? "" : ", peer=" + peer));
    }

    int rc = fpShutdown(s, how);
    if (rc == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (Core::Logger::IsEnabled(Core::LogLevel::Debug)) {
            Core::Logger::Debug("shutdown: 失败, sock=" + std::to_string((unsigned long long)s) +
                                ", WSA错误码=" + std::to_string(err));
        }
        WSASetLastError(err);
    }
    return rc;
}

int WSAAPI DetourCloseSocket(SOCKET s) {
    if (!fpCloseSocket) {
        WSASetLastError(WSAEINVAL);
        return SOCKET_ERROR;
    }

    if (IsLocalBypassSocket(s)) {
        const int result = fpCloseSocket(s);
        const int error = result == SOCKET_ERROR ? WSAGetLastError() : 0;
        if (result == 0) { SetLocalBypassSocket(s, false); std::lock_guard<std::mutex> lock(g_socketModesMutex); g_socketNonblocking.erase(s); }
        if (result == SOCKET_ERROR) WSASetLastError(error);
        return result;
    }

    SocketTargetInfo target{};
    const bool hasTarget = TryGetSocketTarget(s, &target);

    std::string local;
    std::string peer;
    if (Core::Logger::IsEnabled(Core::LogLevel::Debug)) {
        local = GetLocalEndpoint(s);
        peer = GetPeerEndpoint(s);
        const std::string targetStr = hasTarget
            ? (target.host + ":" + std::to_string(target.port))
            : std::string("(未知)");
        Core::Logger::Debug("closesocket: sock=" + std::to_string((unsigned long long)s) +
                            ", target=" + targetStr +
                            (local.empty() ? "" : ", local=" + local) +
                            (peer.empty() ? "" : ", peer=" + peer));
    }

    int rc = fpCloseSocket(s);
    if (rc == SOCKET_ERROR) {
        int err = WSAGetLastError();
        Core::Logger::Warn("closesocket: 失败, sock=" + std::to_string((unsigned long long)s) +
                           ", WSA错误码=" + std::to_string(err));
        WSASetLastError(err);
        return rc;
    }

    // UDP 代理：关闭对应的 UDP Associate 控制连接并清理 Overlapped 上下文
    {
        std::lock_guard<std::mutex> lock(g_connectExMtx);
        for(auto it=g_connectExPending.begin();it!=g_connectExPending.end();) {
            if(it->second.sock==s) it=g_connectExPending.erase(it); else ++it;
        }
    }
    CleanupUdpProxyContext(s);
    { std::lock_guard<std::mutex> lock(g_socketModesMutex); g_socketNonblocking.erase(s); }

    // 关闭成功后清理映射，避免句柄复用导致的误关联
    ForgetSocketTarget(s);
    SetLocalBypassSocket(s, false);

    if (Core::Logger::IsEnabled(Core::LogLevel::Debug)) {
        Core::Logger::Debug("closesocket: 完成, sock=" + std::to_string((unsigned long long)s));
    }
    return rc;
}


int WSAAPI DetourGetAddrInfo(PCSTR node, PCSTR service, const ADDRINFOA* hints, PADDRINFOA* result) {
    int family = hints ? hints->ai_family : AF_UNSPEC;
    if (node && Hooks::ShouldFakeDns(node, ParseServiceNameToPortA(service, "tcp"), family,
            hints ? hints->ai_flags : 0, hints ? hints->ai_socktype : SOCK_STREAM)) {
        auto ip = Network::FakeIP::Instance().Alloc(node);
        if (!ip) return EAI_MEMORY;
        auto numeric = Network::FakeIP::IpToString(ip);
        if (family == AF_INET6) numeric = "::ffff:" + numeric;
        return fpGetAddrInfo(numeric.c_str(), service, hints, result);
    }
    return fpGetAddrInfo(node, service, hints, result);
}
int WSAAPI DetourGetAddrInfoW(PCWSTR node, PCWSTR service, const ADDRINFOW* hints, PADDRINFOW* result) {
    int family = hints ? hints->ai_family : AF_UNSPEC;
    if (node && Hooks::ShouldFakeDns(WideToUtf8(node), ParseServiceNameToPortW(service, "tcp"), family,
            hints ? hints->ai_flags : 0, hints ? hints->ai_socktype : SOCK_STREAM)) {
        auto ip = Network::FakeIP::Instance().Alloc(WideToUtf8(node));
        if (!ip) return EAI_MEMORY;
        return fpGetAddrInfoW(Hooks::StableNumericName(ip, family), service, hints, result);
    }
    return fpGetAddrInfoW(node, service, hints, result);
}
INT WSAAPI DetourGetAddrInfoExW(PCWSTR node, PCWSTR service, DWORD nameSpace, LPGUID provider,
    const ADDRINFOEXW* hints, PADDRINFOEXW* result, timeval* timeout,
    LPOVERLAPPED overlapped, LPLOOKUPSERVICE_COMPLETION_ROUTINE completion, LPHANDLE cancel) {
    int family = hints ? hints->ai_family : AF_UNSPEC;
    const wchar_t* effectiveName = node;
    if (node && (nameSpace == NS_ALL || nameSpace == NS_DNS) &&
        Hooks::ShouldFakeDns(WideToUtf8(node), ParseServiceNameToPortW(service, "tcp"), family,
            hints ? hints->ai_flags : 0, hints ? hints->ai_socktype : SOCK_STREAM)) {
        auto ip = Network::FakeIP::Instance().Alloc(WideToUtf8(node));
        if (!ip) return EAI_MEMORY;
        effectiveName = Hooks::StableNumericName(ip, family);
    }
    // Forward the entire native async contract. Windows owns result allocation,
    // pending/immediate completion, callback timing, hEvent and cancel handles.
    return fpGetAddrInfoExW(effectiveName, service, nameSpace, provider, hints, result,
                           timeout, overlapped, completion, cancel);
}
struct hostent* WSAAPI DetourGetHostByName(const char* name) {
    if (name && Hooks::ShouldFakeDns(name, 0, AF_INET, 0, SOCK_STREAM)) {
        auto ip = Network::FakeIP::Instance().Alloc(name);
        if (!ip) { WSASetLastError(WSA_NOT_ENOUGH_MEMORY); return nullptr; }
        auto numeric = Network::FakeIP::IpToString(ip);
        return fpGetHostByName(numeric.c_str());
    }
    return fpGetHostByName(name);
}
BOOL WINAPI DetourWinHttpIEProxy(WINHTTP_CURRENT_USER_IE_PROXY_CONFIG* config) {
    if (!config) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    *config = {};
    return TRUE;
}
BOOL WINAPI DetourWinHttpProxyForUrl(HINTERNET, LPCWSTR, WINHTTP_AUTOPROXY_OPTIONS*, WINHTTP_PROXY_INFO* info) {
    if (info) *info = {};
    SetLastError(ERROR_WINHTTP_AUTODETECTION_FAILED);
    return FALSE;
}

BOOL WSAAPI DetourWSAConnectByNameA(
    SOCKET s,
    LPCSTR nodename,
    LPCSTR servicename,
    LPDWORD LocalAddressLength,
    LPSOCKADDR LocalAddress,
    LPDWORD RemoteAddressLength,
    LPSOCKADDR RemoteAddress,
    const struct timeval* timeout,
    LPWSAOVERLAPPED Reserved
) {
    std::string node = nodename ? nodename : "";
    std::string service = servicename ? servicename : "";
    std::string msg = "拦截到 WSAConnectByNameA: " + node;
    if (!service.empty()) msg += ":" + service;
    if (Core::Logger::IsEnabled(Core::LogLevel::Debug)) {
        Core::Logger::Debug(msg + ", sock=" + std::to_string((unsigned long long)s));
    }
    if (!fpWSAConnectByNameA) {
        WSASetLastError(WSAEINVAL);
        return FALSE;
    }
    if (Network::IsLoopbackHost(node)) {
        CleanupUdpProxyContext(s);
        ForgetSocketTarget(s);
        const BOOL result = fpWSAConnectByNameA(
            s, nodename, servicename, LocalAddressLength, LocalAddress,
            RemoteAddressLength, RemoteAddress, timeout, Reserved);
        const int error = result ? 0 : WSAGetLastError();
        UpdateLocalBypassSocketAfterConnect(s, result == TRUE, error);
        LogLocalTargetBypass(
            "WSAConnectByNameA", s, service.empty() ? node : node + ":" + service);
        if (!result) WSASetLastError(error);
        return result;
    }
    SetLocalBypassSocket(s, false);
    auto& config = Core::Config::Instance();
    if (config.proxy.port != 0 && !node.empty() && !Reserved) {
        sockaddr_storage targetAddr{};
        int targetLen = 0;
        if (ResolveNameToAddr(s, node, service, config.rules.ipv6_mode, &targetAddr, &targetLen)) {
            // 回填目标地址（如调用方提供缓冲区）
            if (RemoteAddress && RemoteAddressLength && *RemoteAddressLength >= (DWORD)targetLen) {
                memcpy(RemoteAddress, &targetAddr, targetLen);
                *RemoteAddressLength = (DWORD)targetLen;
            }
            int rc;
            if(Network::IsLocalSockaddr(reinterpret_cast<sockaddr*>(&targetAddr),targetLen)) {
                CleanupUdpProxyContext(s); ForgetSocketTarget(s);
                rc=fpConnect(s,reinterpret_cast<sockaddr*>(&targetAddr),targetLen);
                int error=rc==SOCKET_ERROR?WSAGetLastError():0;
                UpdateLocalBypassSocketAfterConnect(s,rc==0,error);
                LogLocalTargetBypass("WSAConnectByName",s,SockaddrToString(reinterpret_cast<sockaddr*>(&targetAddr)));
                if(rc==SOCKET_ERROR) WSASetLastError(error);
            } else rc=PerformProxyConnect(s,reinterpret_cast<sockaddr*>(&targetAddr),targetLen,true);
            if (rc == 0 && LocalAddress && LocalAddressLength) {
                int localLength=static_cast<int>(*LocalAddressLength);
                if (getsockname(s,LocalAddress,&localLength)!=0) return FALSE;
                *LocalAddressLength=static_cast<DWORD>(localLength);
            }
            return rc == 0 ? TRUE : FALSE;
        }
        Core::Logger::Warn("WSAConnectByNameA 解析失败，回退原始实现");
    } else if (Reserved) {
        if (Core::Logger::IsEnabled(Core::LogLevel::Debug)) {
            Core::Logger::Debug("WSAConnectByNameA 使用 Overlapped，回退原始实现, sock=" + std::to_string((unsigned long long)s));
        }
    }
    return fpWSAConnectByNameA(s, nodename, servicename, LocalAddressLength, LocalAddress, RemoteAddressLength, RemoteAddress, timeout, Reserved);
}

BOOL WSAAPI DetourWSAConnectByNameW(
    SOCKET s,
    LPWSTR nodename,
    LPWSTR servicename,
    LPDWORD LocalAddressLength,
    LPSOCKADDR LocalAddress,
    LPDWORD RemoteAddressLength,
    LPSOCKADDR RemoteAddress,
    const struct timeval* timeout,
    LPWSAOVERLAPPED Reserved
) {
    std::string node = WideToUtf8(nodename);
    std::string service = WideToUtf8(servicename);
    std::string msg = "拦截到 WSAConnectByNameW: " + node;
    if (!service.empty()) msg += ":" + service;
    if (Core::Logger::IsEnabled(Core::LogLevel::Debug)) {
        Core::Logger::Debug(msg + ", sock=" + std::to_string((unsigned long long)s));
    }
    if (!fpWSAConnectByNameW) {
        WSASetLastError(WSAEINVAL);
        return FALSE;
    }
    if (Network::IsLoopbackHost(node)) {
        CleanupUdpProxyContext(s);
        ForgetSocketTarget(s);
        const BOOL result = fpWSAConnectByNameW(
            s, nodename, servicename, LocalAddressLength, LocalAddress,
            RemoteAddressLength, RemoteAddress, timeout, Reserved);
        const int error = result ? 0 : WSAGetLastError();
        UpdateLocalBypassSocketAfterConnect(s, result == TRUE, error);
        LogLocalTargetBypass(
            "WSAConnectByNameW", s, service.empty() ? node : node + ":" + service);
        if (!result) WSASetLastError(error);
        return result;
    }
    SetLocalBypassSocket(s, false);
    auto& config = Core::Config::Instance();
    if (config.proxy.port != 0 && !node.empty() && !Reserved) {
        sockaddr_storage targetAddr{};
        int targetLen = 0;
        if (ResolveNameToAddr(s, node, service, config.rules.ipv6_mode, &targetAddr, &targetLen)) {
            // 回填目标地址（如调用方提供缓冲区）
            if (RemoteAddress && RemoteAddressLength && *RemoteAddressLength >= (DWORD)targetLen) {
                memcpy(RemoteAddress, &targetAddr, targetLen);
                *RemoteAddressLength = (DWORD)targetLen;
            }
            int rc;
            if(Network::IsLocalSockaddr(reinterpret_cast<sockaddr*>(&targetAddr),targetLen)) {
                CleanupUdpProxyContext(s); ForgetSocketTarget(s);
                rc=fpConnect(s,reinterpret_cast<sockaddr*>(&targetAddr),targetLen);
                int error=rc==SOCKET_ERROR?WSAGetLastError():0;
                UpdateLocalBypassSocketAfterConnect(s,rc==0,error);
                LogLocalTargetBypass("WSAConnectByName",s,SockaddrToString(reinterpret_cast<sockaddr*>(&targetAddr)));
                if(rc==SOCKET_ERROR) WSASetLastError(error);
            } else rc=PerformProxyConnect(s,reinterpret_cast<sockaddr*>(&targetAddr),targetLen,true);
            if (rc == 0 && LocalAddress && LocalAddressLength) {
                int localLength=static_cast<int>(*LocalAddressLength);
                if (getsockname(s,LocalAddress,&localLength)!=0) return FALSE;
                *LocalAddressLength=static_cast<DWORD>(localLength);
            }
            return rc == 0 ? TRUE : FALSE;
        }
        Core::Logger::Warn("WSAConnectByNameW 解析失败，回退原始实现");
    } else if (Reserved) {
        if (Core::Logger::IsEnabled(Core::LogLevel::Debug)) {
            Core::Logger::Debug("WSAConnectByNameW 使用 Overlapped，回退原始实现, sock=" + std::to_string((unsigned long long)s));
        }
    }
    return fpWSAConnectByNameW(s, nodename, servicename, LocalAddressLength, LocalAddress, RemoteAddressLength, RemoteAddress, timeout, Reserved);
}

int WSAAPI DetourWSAIoctl(
    SOCKET s,
    DWORD dwIoControlCode,
    LPVOID lpvInBuffer,
    DWORD cbInBuffer,
    LPVOID lpvOutBuffer,
    DWORD cbOutBuffer,
    LPDWORD lpcbBytesReturned,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
) {
    if (!fpWSAIoctl) return SOCKET_ERROR;
    if (IsLocalBypassSocket(s)) {
        return fpWSAIoctl(
            s, dwIoControlCode, lpvInBuffer, cbInBuffer, lpvOutBuffer,
            cbOutBuffer, lpcbBytesReturned, lpOverlapped, lpCompletionRoutine);
    }
    int result = fpWSAIoctl(s, dwIoControlCode, lpvInBuffer, cbInBuffer, lpvOutBuffer, cbOutBuffer,
                            lpcbBytesReturned, lpOverlapped, lpCompletionRoutine);
    if(result==0 && dwIoControlCode==FIONBIO && lpvInBuffer && cbInBuffer>=sizeof(u_long))
        RememberSocketMode(s,*static_cast<u_long*>(lpvInBuffer)!=0);
    if (result == 0 && dwIoControlCode == SIO_GET_EXTENSION_FUNCTION_POINTER &&
        lpvInBuffer && cbInBuffer == sizeof(GUID) &&
        lpvOutBuffer && cbOutBuffer >= sizeof(LPFN_CONNECTEX)) {
        GUID guid = *(GUID*)lpvInBuffer;
        if (IsEqualGUID(guid, WSAID_CONNECTEX)) {
            LPFN_CONNECTEX connectEx = *(LPFN_CONNECTEX*)lpvOutBuffer;
            if (connectEx) {
                // ConnectEx 指针可能随 Provider 不同而不同：按 CatalogEntryId 去重安装
                DWORD catalogId = 0;
                const bool hasCatalog = TryGetSocketCatalogEntryId(s, &catalogId);
                void* targetKey = (void*)connectEx;

                std::lock_guard<std::mutex> lock(g_connectExHookMtx);

                // 已安装过该 Provider 的 ConnectEx Hook
                if (hasCatalog) {
                    auto it = g_connectExOriginalByCatalog.find(catalogId);
                    if (it != g_connectExOriginalByCatalog.end() && it->second) {
                        return result;
                    }
                } else if (fpConnectEx) {
                    // 无法获取 Catalog 时，至少保证单 Provider 兜底已存在
                    return result;
                }

                // 如果该 ConnectEx 目标指针已被 Hook，则复用 trampoline 并补全 Catalog 映射（解决多 Provider 环境缺口）
                {
                    auto itTarget = g_connectExTrampolineByTarget.find(targetKey);
                    if (itTarget != g_connectExTrampolineByTarget.end() && itTarget->second) {
                        if (hasCatalog) {
                            g_connectExOriginalByCatalog[catalogId] = itTarget->second;
                        }
                        if (!fpConnectEx) fpConnectEx = itTarget->second;
                        std::string detail = hasCatalog ? (", CatalogEntryId=" + std::to_string(catalogId)) : ", CatalogEntryId=未知";
                        Core::Logger::Info("ConnectEx Hook 已复用" + detail);
                        return result;
                    }
                }

                LPFN_CONNECTEX originalFn = nullptr;
                MH_STATUS st = MH_CreateHook((LPVOID)connectEx, (LPVOID)DetourConnectEx, (LPVOID*)&originalFn);
                if (st == MH_ERROR_ALREADY_CREATED) {
                    // 目标指针已存在 Hook（并发/复用场景），尝试复用已记录 trampoline
                    auto itTarget = g_connectExTrampolineByTarget.find(targetKey);
                    if (itTarget != g_connectExTrampolineByTarget.end() && itTarget->second) {
                        if (hasCatalog) {
                            g_connectExOriginalByCatalog[catalogId] = itTarget->second;
                        }
                        if (!fpConnectEx) fpConnectEx = itTarget->second;
                        std::string detail = hasCatalog ? (", CatalogEntryId=" + std::to_string(catalogId)) : ", CatalogEntryId=未知";
                        Core::Logger::Info("ConnectEx Hook 已复用" + detail);
                    } else {
                        std::string detail = hasCatalog ? (", CatalogEntryId=" + std::to_string(catalogId)) : ", CatalogEntryId=未知";
                        Core::Logger::Warn("ConnectEx Hook 已存在但无法复用 trampoline" + detail);
                    }
                } else if (st != MH_OK) {
                    Core::Logger::Error("Hook ConnectEx 失败");
                } else if (MH_EnableHook((LPVOID)connectEx) != MH_OK) {
                    Core::Logger::Error("启用 ConnectEx Hook 失败");
                } else {
                    g_connectExTrampolineByTarget[targetKey] = originalFn;
                    if (hasCatalog) {
                        g_connectExOriginalByCatalog[catalogId] = originalFn;
                    }
                    // 保留一个兜底 trampoline，兼容无法获取 Catalog 的极端场景
                    if (!fpConnectEx) fpConnectEx = originalFn;
                    std::string detail;
                    if (hasCatalog) {
                        detail += ", CatalogEntryId=" + std::to_string(catalogId);
                    } else {
                        detail += ", CatalogEntryId=未知";
                    }
                    Core::Logger::Info("ConnectEx Hook 已安装" + detail);
                }
            }
        }
    }
    return result;
}

BOOL PASCAL DetourConnectEx(
    SOCKET s,
    const struct sockaddr* name,
    int namelen,
    PVOID lpSendBuffer,
    DWORD dwSendDataLength,
    LPDWORD lpdwBytesSent,
    LPOVERLAPPED lpOverlapped
) {
    BeginOverlappedOperation(lpOverlapped);
    // ConnectEx trampoline 可能因 Provider 不同而不同，这里按 socket Provider 选择对应的原始实现
    LPFN_CONNECTEX originalConnectEx = GetOriginalConnectExForSocket(s);
    if (!originalConnectEx) {
        WSASetLastError(WSAEINVAL);
        return FALSE;
    }
    // 基础参数校验，避免空指针/长度不足导致崩溃
    if (!name) {
        WSASetLastError(WSAEFAULT);
        return FALSE;
    }
    if (namelen < (int)sizeof(sockaddr)) {
        WSASetLastError(WSAEINVAL);
        return FALSE;
    }
    if (name->sa_family == AF_INET && namelen < (int)sizeof(sockaddr_in)) {
        WSASetLastError(WSAEINVAL);
        return FALSE;
    }
    if (name->sa_family == AF_INET6 && namelen < (int)sizeof(sockaddr_in6)) {
        WSASetLastError(WSAEINVAL);
        return FALSE;
    }

    if (Network::IsLocalSockaddr(name, namelen)) {
        DropConnectExContext(lpOverlapped);
        DropUdpOverlappedContext(lpOverlapped);
        CleanupUdpProxyContext(s);
        ForgetSocketTarget(s);
        const BOOL result = originalConnectEx(
            s, name, namelen, lpSendBuffer, dwSendDataLength,
            lpdwBytesSent, lpOverlapped);
        const int error = result ? 0 : WSAGetLastError();
        UpdateLocalBypassSocketAfterConnect(s, result == TRUE, error);
        LogLocalTargetBypass("ConnectEx", s, SockaddrToString(name));
        if (!result) WSASetLastError(error);
        return result;
    }
    SetLocalBypassSocket(s, false);
    
    // Hook 调用日志：仅在 Debug 下记录参数，避免热路径字符串拼接开销
    if (Core::Logger::IsEnabled(Core::LogLevel::Debug)) {
        const std::string dst = SockaddrToString(name);
        Core::Logger::Debug("ConnectEx: 调用, sock=" + std::to_string((unsigned long long)s) +
                            ", dst=" + (dst.empty() ? "(未知)" : dst) +
                            ", send_len=" + std::to_string((unsigned long long)dwSendDataLength) +
                            ", overlapped=" + std::to_string((unsigned long long)(ULONG_PTR)lpOverlapped));
    }

    auto& config = Core::Config::Instance();
    LogRuntimeConfigSummaryOnce();
    Network::SocketWrapper sock(s);
    sock.SetTimeouts(config.timeout.recv_ms, config.timeout.send_ms);
    
    // 仅对 TCP (SOCK_STREAM) 做代理，避免误伤 UDP/QUIC 等
    if (config.proxy.port != 0) {
        const int soType = GetSocketTypeForProxyDecision(s);
        if (soType != SOCK_STREAM) {

            if (soType == SOCK_DGRAM) {
                // ConnectEx 也按统一有效策略处理 UDP，避免遗漏 QUIC/HTTP3 路径。
                if (IsBlockedUdpV6(name)) { WSASetLastError(WSAEACCES); return FALSE; }
            const Core::UdpAction udpAction = GetEffectiveUdpAction(config);
                if (udpAction == Core::UdpAction::Block) {
                    uint16_t dstPort = 0;
                    const bool hasPort = TryGetSockaddrPort(name, &dstPort);
                    // 例外判断统一收敛到 IsUdpBlockExempt（loopback / UDP53 / 局域网等 direct 路由规则）
                    const bool allowUdp = IsUdpBlockExempt(config, name, hasPort, dstPort);
                    if (!allowUdp) {
                        const int err = WSAEACCES;
                        if (ShouldLogUdpBlock()) {
                            const std::string dst = SockaddrToString(name);
                            Core::Logger::Warn("ConnectEx: 已阻止 UDP 连接(策略: " + GetUdpPolicyLabel(config) + "), sock=" + std::to_string((unsigned long long)s) +
                                               (dst.empty() ? "" : ", dst=" + dst) +
                                               (hasPort ? (", port=" + std::to_string(dstPort)) : std::string("")) +
                                               ", WSA错误码=" + std::to_string(err));
                        }
                        WSASetLastError(err);
                        return FALSE;
                    }
                    if (Core::Logger::IsEnabled(Core::LogLevel::Debug)) {
                        const std::string dst = SockaddrToString(name);
                        Core::Logger::Debug("ConnectEx: UDP 直连已放行(例外), sock=" + std::to_string((unsigned long long)s) +
                                            (dst.empty() ? "" : ", dst=" + dst));
                    }
                    return originalConnectEx(s, name, namelen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped);
                }

                // UDP 走代理：通过 SOCKS5 UDP Associate 转发（用于 QUIC/HTTP3）
                if (udpAction == Core::UdpAction::Proxy) {
                    return PerformProxyUdpConnectEx(s, name, namelen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped, originalConnectEx);
                }

                // 有效策略为 direct：保持直连
                return originalConnectEx(s, name, namelen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped);
            }

            // 其他非 SOCK_STREAM 类型保持直连；仅在 Debug 下记录，避免刷屏影响性能
            if (Core::Logger::IsEnabled(Core::LogLevel::Debug)) {
                const std::string dst = SockaddrToString(name);
                Core::Logger::Debug("ConnectEx: 非 SOCK_STREAM 直连, sock=" + std::to_string((unsigned long long)s) +
                                    ", soType=" + std::to_string(soType) +
                                    (dst.empty() ? "" : ", dst=" + dst));
            }
            return originalConnectEx(s, name, namelen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped);
        }
    }

    if (name->sa_family == AF_INET6) {
        const auto* addr6 = (const sockaddr_in6*)name;
        const bool isV4Mapped = IN6_IS_ADDR_V4MAPPED(&addr6->sin6_addr);

        // v4-mapped IPv6 本质是 IPv4 连接：不应被 ipv6_mode 误伤（否则会影响 FakeIP v4-mapped 回填）
        if (!isV4Mapped) {
            // WARN-5: 同 PerformProxyConnect：纯 IPv6 连接先按 ipv6_mode 决策，仅 ipv6_mode=proxy 时才继续 routing
            std::string addrStr = SockaddrToString(name);
            if (config.proxy.port != 0) {
                const std::string& ipv6Mode = config.rules.ipv6_mode;
                if (ipv6Mode == "direct") {
                    Core::Logger::Info("ConnectEx IPv6 连接已直连(策略: direct), sock=" + std::to_string((unsigned long long)s) +
                                       ", family=" + std::to_string((int)name->sa_family) +
                                       (addrStr.empty() ? "" : ", addr=" + addrStr));
                    return originalConnectEx(s, name, namelen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped);
                }
                if (ipv6Mode != "proxy") {
                    // 强制阻止 IPv6，避免绕过代理
                    Core::Logger::Warn("ConnectEx 已阻止 IPv6 连接(策略: block), sock=" + std::to_string((unsigned long long)s) +
                                       ", family=" + std::to_string((int)name->sa_family) +
                                       (addrStr.empty() ? "" : ", addr=" + addrStr));
                    WSASetLastError(WSAEAFNOSUPPORT);
                    return FALSE;
                }
            } else {
                Core::Logger::Info("ConnectEx IPv6 连接已直连, sock=" + std::to_string((unsigned long long)s) +
                                   ", family=" + std::to_string((int)name->sa_family) +
                                   (addrStr.empty() ? "" : ", addr=" + addrStr));
                return originalConnectEx(s, name, namelen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped);
            }
        }
    } else if (name->sa_family != AF_INET) {
        std::string addrStr = SockaddrToString(name);
        if (config.proxy.port != 0) {
            // 非 IPv4/IPv6 连接一律阻止，避免绕过代理
            Core::Logger::Warn("ConnectEx 已阻止非 IPv4/IPv6 连接, sock=" + std::to_string((unsigned long long)s) +
                               ", family=" + std::to_string((int)name->sa_family) +
                               (addrStr.empty() ? "" : ", addr=" + addrStr));
            WSASetLastError(WSAEAFNOSUPPORT);
            return FALSE;
        }
        Core::Logger::Info("ConnectEx 非 IPv4/IPv6 连接已直连, sock=" + std::to_string((unsigned long long)s) +
                           ", family=" + std::to_string((int)name->sa_family) +
                           (addrStr.empty() ? "" : ", addr=" + addrStr));
        return originalConnectEx(s, name, namelen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped);
    }
    
    std::string originalHost;
    uint16_t originalPort = 0;
    if (!ResolveOriginalTarget(name, &originalHost, &originalPort)) {
        return originalConnectEx(s, name, namelen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped);
    }
    
    if (IsLoopbackHost(originalHost)) {
        if (Core::Logger::IsEnabled(Core::LogLevel::Debug)) {
            Core::Logger::Debug("ConnectEx BYPASS(loopback): sock=" + std::to_string((unsigned long long)s) +
                                ", target=" + originalHost + ":" + std::to_string(originalPort));
        }
        return originalConnectEx(s, name, namelen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped);
    }
    if (IsProxySelfTarget(originalHost, originalPort, config.proxy)) {
        if (Core::Logger::IsEnabled(Core::LogLevel::Debug)) {
            Core::Logger::Debug("ConnectEx BYPASS(proxy-self): sock=" + std::to_string((unsigned long long)s) +
                                ", target=" + originalHost + ":" + std::to_string(originalPort) +
                                ", proxy=" + config.proxy.host + ":" + std::to_string(config.proxy.port));
        }
        return originalConnectEx(s, name, namelen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped);
    }

    // ROUTE-0: 自定义路由规则（域名/CIDR/端口/协议）
    std::string addrIp;
    bool addrIsV6 = false;
    SockaddrToIp(name, &addrIp, &addrIsV6);
    std::string routeAction;
    std::string routeRule;
    const bool routeMatched = config.rules.MatchRouting(originalHost, addrIp, addrIsV6, originalPort, "tcp",
                                                        &routeAction, &routeRule);
    if (!routeAction.empty() && routeAction == "direct") {
        if (ShouldLogRouteDecisionInfo()) {
            Core::Logger::Info("[Route] direct" +
                               std::string(routeMatched ? (" rule=" + routeRule) : " rule=(default)") +
                               ", target=" + originalHost + ":" + std::to_string(originalPort));
        }
        // CRIT-3: direct + FakeIP 兜底重解析，避免“直连虚拟地址”必失败
        sockaddr_storage directAddr{};
        int directLen = 0;
        const sockaddr* direct = ResolveDirectTarget(name, namelen, originalHost, originalPort, "[Route] direct(ConnectEx)",
                                                     &directAddr, &directLen);
        return originalConnectEx(s, direct, directLen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped);
    } else if (routeMatched) {
        if (ShouldLogRouteDecisionInfo()) {
            Core::Logger::Info("[Route] proxy rule=" + routeRule +
                               ", target=" + originalHost + ":" + std::to_string(originalPort));
        }
    }
    
    if (config.proxy.port == 0) {
        return originalConnectEx(s, name, namelen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped);
    }

    // ============= 智能路由决策（与 PerformProxyConnect 保持一致） =============
    // ROUTE-1: DNS 端口特殊处理 (解决 DNS 超时问题)
    if (originalPort == 53) {
        if (config.rules.dns_mode == "direct" || config.rules.dns_mode.empty()) {
            if (ShouldLogRouteDecisionInfo()) {
                Core::Logger::Info("ConnectEx DNS 请求直连 (策略: direct), sock=" + std::to_string((unsigned long long)s) +
                                   ", 目标: " + originalHost + ":53");
            }
            // 与 connect 路径一致：域名形式的 DNS 服务器持有 FakeIP，直连前还原
            sockaddr_storage directAddr{};
            int directLen = 0;
            const sockaddr* direct = ResolveDirectTarget(name, namelen, originalHost, originalPort, "ConnectEx DNS 直连",
                                                         &directAddr, &directLen);
            return originalConnectEx(s, direct, directLen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped);
        }
        // dns_mode == "proxy" 则继续走后面的代理逻辑
        if (ShouldLogRouteDecisionInfo()) {
            Core::Logger::Info("ConnectEx DNS 请求走代理 (策略: proxy), sock=" + std::to_string((unsigned long long)s) +
                               ", 目标: " + originalHost + ":53");
        }
    }

    // ROUTE-2: 端口白名单过滤
    if (!(originalPort == 53 && config.rules.dns_mode == "proxy") && !config.rules.IsPortAllowed(originalPort)) {
        if (ShouldLogRouteDecisionInfo()) {
            Core::Logger::Info("ConnectEx 端口 " + std::to_string(originalPort) + " 不在白名单, sock=" + std::to_string((unsigned long long)s) +
                               ", 直连: " + originalHost);
        }
        // 与 connect 路径一致：白名单外端口的域名连接持有 FakeIP，直连前还原
        sockaddr_storage directAddr{};
        int directLen = 0;
        const sockaddr* direct = ResolveDirectTarget(name, namelen, originalHost, originalPort, "ConnectEx 端口白名单外直连",
                                                     &directAddr, &directLen);
        return originalConnectEx(s, direct, directLen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped);
    }
    
    if (ShouldLogRouteDecisionInfo()) {
        Core::Logger::Info("ConnectEx 正重定向 " + originalHost + ":" + std::to_string(originalPort) +
                           " 到代理, sock=" + std::to_string((unsigned long long)s));
    }
    

    if (!lpOverlapped) { WSASetLastError(WSAEINVAL); return FALSE; }
    sockaddr_storage proxyAddress{};
    int proxyLength=0;
    if(name->sa_family==AF_INET6) {
        auto* p6=reinterpret_cast<sockaddr_in6*>(&proxyAddress);
        if(!BuildProxyAddrV6(config.proxy,p6,reinterpret_cast<const sockaddr_in6*>(name)) ||
           !PrepareIpv4MappedProxyDestination(s,*p6)) return FALSE;
        proxyLength=sizeof(sockaddr_in6);
    } else {
        if(!BuildProxyAddr(config.proxy,reinterpret_cast<sockaddr_in*>(&proxyAddress),
                           reinterpret_cast<const sockaddr_in*>(name))) { WSASetLastError(WSAEINVAL); return FALSE; }
        proxyLength=sizeof(sockaddr_in);
    }
    ConnectExContext ctx{};
    ctx.sock=s; ctx.host=originalHost; ctx.port=originalPort;
    ctx.sendBuf=static_cast<const char*>(lpSendBuffer); ctx.sendLen=dwSendDataLength;
    // Publish before the provider can queue a completion on another thread.
    SaveConnectExContext(lpOverlapped,ctx);
    BOOL result=originalConnectEx(s,reinterpret_cast<sockaddr*>(&proxyAddress),proxyLength,
                                 nullptr,0,nullptr,lpOverlapped);
    if(!result) {
        int error=WSAGetLastError();
        if(error!=WSA_IO_PENDING) DropConnectExContext(lpOverlapped);
        WSASetLastError(error); return FALSE;
    }
    DWORD sent=0;
    if(!HandleConnectExCompletion(lpOverlapped,&sent)) return FALSE;
    if(lpdwBytesSent) *lpdwBytesSent=sent;
    return TRUE;
}

BOOL WSAAPI DetourWSAGetOverlappedResult(
    SOCKET s,
    LPWSAOVERLAPPED lpOverlapped,
    LPDWORD lpcbTransfer,
    BOOL fWait,
    LPDWORD lpdwFlags
) {
    if (!fpWSAGetOverlappedResult) {
        WSASetLastError(WSAEINVAL);
        return FALSE;
    }
    if (IsLocalBypassSocket(s)) {
        return fpWSAGetOverlappedResult(s, lpOverlapped, lpcbTransfer, fWait, lpdwFlags);
    }
    BOOL result = fpWSAGetOverlappedResult(s, lpOverlapped, lpcbTransfer, fWait, lpdwFlags);
    if (result && lpOverlapped) {
        DWORD sentBytes = 0;
        if (!HandleConnectExCompletion(lpOverlapped, &sentBytes)) {
            if (WSAGetLastError() == 0) WSASetLastError(WSAECONNREFUSED);
            return FALSE;
        }
        // ConnectEx 带首包时，原始返回的 lpcbTransfer 可能为 0，这里回填为实际发送字节数
        if (sentBytes > 0 && lpcbTransfer) {
            *lpcbTransfer = sentBytes;
        }

        // UDP/QUIC：对 UDP Overlapped 的 bytes/缓冲区做修正（解封装 SOCKS5 UDP 头）
        if (lpcbTransfer) {
            DWORD userBytes = 0;
            const DWORD internalBytes = *lpcbTransfer;
            int error=0;
            if (HandleUdpOverlappedCompletion(lpOverlapped, internalBytes, &userBytes, &error)) {
                *lpcbTransfer = userBytes;
                if(error) { WSASetLastError(error); return FALSE; }
            }
        }
    } else if (!result && lpOverlapped) {
        int err = WSAGetLastError();
        if (err != WSA_IO_INCOMPLETE) {
            DropConnectExContext(lpOverlapped);
            DropUdpOverlappedContext(lpOverlapped);
        }
    }
    return result;
}

BOOL WINAPI DetourGetQueuedCompletionStatus(
    HANDLE CompletionPort,
    LPDWORD lpNumberOfBytes,
    PULONG_PTR lpCompletionKey,
    LPOVERLAPPED* lpOverlapped,
    DWORD dwMilliseconds
) {
    if (!fpGetQueuedCompletionStatus) {
        SetLastError(ERROR_INVALID_FUNCTION);
        return FALSE;
    }
    BOOL result = fpGetQueuedCompletionStatus(CompletionPort, lpNumberOfBytes, lpCompletionKey, lpOverlapped, dwMilliseconds);
    if (result && lpOverlapped && *lpOverlapped) {
        // FIX-1: 单事件版本 - result=TRUE 表示 IOCP 操作成功
        DWORD sentBytes = 0;
        if (!HandleConnectExCompletion(*lpOverlapped, &sentBytes)) {
            SetLastError(ERROR_CONNECTION_REFUSED);
            return FALSE;
        }
        if (sentBytes > 0 && lpNumberOfBytes) {
            *lpNumberOfBytes = sentBytes;
        }

        // UDP/QUIC：在 IOCP 出队前解封装并修正 bytesTransferred
        if (lpNumberOfBytes) {
            DWORD userBytes = 0;
            const DWORD internalBytes = *lpNumberOfBytes;
            int error=0;
            if (HandleUdpOverlappedCompletion(*lpOverlapped, internalBytes, &userBytes, &error, true)) {
                *lpNumberOfBytes = userBytes;
                if(error) { SetLastError(error); return FALSE; }
            }
        }
    } else if (!result && lpOverlapped && *lpOverlapped) {
        DropConnectExContext(*lpOverlapped);
        DropUdpOverlappedContext(*lpOverlapped);
    }
    return result;
}

// GetQueuedCompletionStatusEx Hook - 批量获取 IOCP 事件
// 现代高性能应用（Chromium/Rust/Go）使用此 API 提高吞吐量，
// 如果不 Hook 此函数，ConnectEx 完成后的代理握手将被跳过
BOOL WINAPI DetourGetQueuedCompletionStatusEx(
    HANDLE CompletionPort,
    LPOVERLAPPED_ENTRY lpCompletionPortEntries,
    ULONG ulCount,
    PULONG ulNumEntriesRemoved,
    DWORD dwMilliseconds,
    BOOL fAlertable
) {
    if (!fpGetQueuedCompletionStatusEx) {
        SetLastError(ERROR_INVALID_FUNCTION);
        return FALSE;
    }
    
    // 调用原始函数获取批量 IOCP 事件
    BOOL result = fpGetQueuedCompletionStatusEx(
        CompletionPort, lpCompletionPortEntries, ulCount,
        ulNumEntriesRemoved, dwMilliseconds, fAlertable
    );
    
    if (result && lpCompletionPortEntries && ulNumEntriesRemoved && *ulNumEntriesRemoved > 0) {
        // FIX-1: 遍历所有完成的事件，检查 IOCP 完成状态后再处理
        for (ULONG i = 0; i < *ulNumEntriesRemoved; i++) {
            LPOVERLAPPED ovl = lpCompletionPortEntries[i].lpOverlapped;
            if (!ovl) continue;
            
            // FIX-1: 检查 IOCP 完成状态（Internal 字段存储 NTSTATUS，本质是 LONG）
            // STATUS_SUCCESS = 0，非零表示操作失败（如连接被拒绝、超时等）
            // 注意：Internal 字段在 OVERLAPPED_ENTRY 中类型为 ULONG_PTR
            LONG ioStatus = (LONG)lpCompletionPortEntries[i].Internal;
            if (ioStatus != 0) {
                // 连接失败：清理上下文，继续处理下一个事件（不阻断整个批次）
                if (Core::Logger::IsEnabled(Core::LogLevel::Debug)) {
                    Core::Logger::Debug("GetQueuedCompletionStatusEx: IOCP 事件失败, status=" + 
                                        std::to_string(ioStatus) + ", 跳过握手");
                }
                DropConnectExContext(ovl);
                DropUdpOverlappedContext((LPWSAOVERLAPPED)ovl);
                continue;
            }
            
            // 连接成功：尝试处理 ConnectEx 完成握手
            // 如果不是我们跟踪的 Overlapped，HandleConnectExCompletion 会直接返回 true
            DWORD sentBytes = 0;
            if (!HandleConnectExCompletion(ovl, &sentBytes)) {
                lpCompletionPortEntries[i].Internal = static_cast<ULONG_PTR>(0xC0000236u);
                lpCompletionPortEntries[i].dwNumberOfBytesTransferred = 0;
                continue;
            }
            if (sentBytes > 0) {
                // 回填 ConnectEx 首包发送字节数，提升与标准 ConnectEx 语义的一致性
                lpCompletionPortEntries[i].dwNumberOfBytesTransferred = sentBytes;
            }

            // UDP/QUIC：在 IOCP 出队前解封装并修正 bytesTransferred
            DWORD userBytes = 0;
            const DWORD internalBytes = lpCompletionPortEntries[i].dwNumberOfBytesTransferred;
            int error=0;
            if (HandleUdpOverlappedCompletion((LPWSAOVERLAPPED)ovl, internalBytes, &userBytes, &error, true)) {
                lpCompletionPortEntries[i].dwNumberOfBytesTransferred = userBytes;
                if(error) lpCompletionPortEntries[i].Internal=ovl->Internal;
            }
        }
    } else if (!result && lpCompletionPortEntries && ulNumEntriesRemoved && *ulNumEntriesRemoved > 0) {
        // 失败时清理残留上下文，避免 Overlapped 复用导致错配
        for (ULONG i = 0; i < *ulNumEntriesRemoved; i++) {
            LPOVERLAPPED ovl = lpCompletionPortEntries[i].lpOverlapped;
            if (ovl) {
                DropConnectExContext(ovl);
                DropUdpOverlappedContext((LPWSAOVERLAPPED)ovl);
            }
        }
    }
    
    return result;
}

// ============= Phase 2: CreateProcessW Hook =============

// 目标子进程创建失败时的诊断日志（Issue #159）：
// 原逻辑仅在 CreateProcess 成功后记录“注入/跳过”，若目标进程（例如 IDE 2.6.0 起由扩展下载到
// ~/.gemini/bin 的 agy.exe --hub 后端）因文件缺失、下载不完整或被安全软件拦截而创建失败，
// 日志中完全没有痕迹，无法区分“未注入”与“根本没启动”。
// 仅对命中 target_processes 的目标记录，避免普通子进程失败刷屏；LastError 由调用方负责恢复。

static void InjectCreatedChild(const PROCESS_INFORMATION& pi, DWORD originalFlags) {
    std::string failure;
    // Attach requests need not exist in the parent's environment. Propagate the
    // actual loaded path while the child is suspended, and retain the mapping
    // until InjectDll has waited for the child's Ready event.
    HANDLE request=Core::CreateLaunchRequest(pi.dwProcessId,Core::Config::Instance().loadedPath);
    bool ok=false;
    if(request) {
        ok=Injection::ProcessInjector::InjectDll(pi.hProcess,
            Injection::ProcessInjector::GetCurrentDllPath(), &failure);
        CloseHandle(request);
    } else failure="Cannot publish child configuration request";
    if (!ok) Core::Logger::Error("Child injection failed: " + failure);
    if (!(originalFlags & CREATE_SUSPENDED)) {
        if (ResumeThread(pi.hThread) == static_cast<DWORD>(-1))
            Core::Logger::Error("ResumeThread failed for target child");
    }
}
BOOL WINAPI DetourCreateProcessW(LPCWSTR app, LPWSTR cmd, LPSECURITY_ATTRIBUTES pa,
    LPSECURITY_ATTRIBUTES ta, BOOL inherit, DWORD flags, LPVOID env, LPCWSTR cwd,
    LPSTARTUPINFOW startup, LPPROCESS_INFORMATION pi) {
    auto name = GetCreateProcessTargetBaseNameW(app, cmd);
    auto& config = Core::Config::Instance();
    bool inject = config.ShouldInjectChildProcess(name) &&
        Hooks::IsInjectableRole(Hooks::ClassifyProcess(name, WideToUtf8(cmd)));
    BOOL result = fpCreateProcessW(app, cmd, pa, ta, inherit,
        inject ? flags | CREATE_SUSPENDED : flags, env, cwd, startup, pi);
    DWORD error = GetLastError();
    if (result && inject && pi) InjectCreatedChild(*pi, flags);
    SetLastError(error);
    return result;
}
BOOL WINAPI DetourCreateProcessA(LPCSTR app, LPSTR cmd, LPSECURITY_ATTRIBUTES pa,
    LPSECURITY_ATTRIBUTES ta, BOOL inherit, DWORD flags, LPVOID env, LPCSTR cwd,
    LPSTARTUPINFOA startup, LPPROCESS_INFORMATION pi) {
    auto name = GetCreateProcessTargetBaseNameA(app, cmd);
    auto& config = Core::Config::Instance();
    bool inject = config.ShouldInjectChildProcess(name) &&
        Hooks::IsInjectableRole(Hooks::ClassifyProcess(name, cmd ? cmd : ""));
    BOOL result = fpCreateProcessA(app, cmd, pa, ta, inherit,
        inject ? flags | CREATE_SUSPENDED : flags, env, cwd, startup, pi);
    DWORD error = GetLastError();
    if (result && inject && pi) InjectCreatedChild(*pi, flags);
    SetLastError(error);
    return result;
}


int WSAAPI DetourSend(SOCKET s, const char* buf, int len, int flags) {
    if (len < 0 || (!buf && len)) return fpSend(s,buf,len,flags);
    if (IsLocalBypassSocket(s)) {
        return fpSend(s, buf, len, flags);
    }
    auto& config = Core::Config::Instance();

    // UDP/QUIC：若该 UDP socket 已进入 udp_mode=proxy，则需要封装为 SOCKS5 UDP 报文
    if (config.proxy.port != 0 && GetEffectiveUdpAction(config) == Core::UdpAction::Proxy) {
        int soType = 0;
        if (TryGetSocketType(s, &soType) && soType == SOCK_DGRAM) {
            std::string host;
            uint16_t port = 0;
            if (TryGetUdpProxyDefaultTarget(s, &host, &port) && !host.empty() && port != 0) {
                sockaddr_storage local{};
                int localLen = (int)sizeof(local);
                const int family = (getsockname(s, (sockaddr*)&local, &localLen) == 0) ? (int)local.ss_family : AF_INET;

                if (!EnsureUdpProxyReady(s, family, host, port, true)) {
                    return SOCKET_ERROR;
                }

                std::vector<uint8_t> packet;
                if (!Network::Socks5Udp::Wrap(host, port, (const uint8_t*)buf, (size_t)len, &packet)) {
                    WSASetLastError(WSAECONNREFUSED);
                    return SOCKET_ERROR;
                }

                if (!SendUdpPacketWithRetry(s, packet.data(), (int)packet.size(), flags, config.timeout.send_ms)) {
                    return SOCKET_ERROR;
                }

                // 流量监控日志：记录用户 payload（不含 SOCKS5 UDP 头）
                Network::TrafficMonitor::Instance().LogSend(s, buf, len);
                return len;
            }
        }
    }

    // 默认：保持原语义
    Network::TrafficMonitor::Instance().LogSend(s, buf, len);
    return fpSend(s, buf, len, flags);
}

int WSAAPI DetourRecv(SOCKET s, char* buf, int len, int flags) {
    if (len < 0 || (!buf && len)) return fpRecv(s,buf,len,flags);
    if (IsLocalBypassSocket(s)) {
        return fpRecv(s, buf, len, flags);
    }
    auto& config = Core::Config::Instance();

    // UDP/QUIC：若该 UDP socket 已进入 udp_mode=proxy，则 recv 得到的是 SOCKS5 UDP Reply，需要解封装
    if (config.proxy.port != 0 && GetEffectiveUdpAction(config) == Core::UdpAction::Proxy) {
        int soType = 0;
        if (TryGetSocketType(s, &soType) && soType == SOCK_DGRAM) {
            sockaddr_storage relay{};
            int relayLen = 0;
            if (TryGetUdpRelayAddr(s, &relay, &relayLen)) {
                const int cap = len + (int)Network::Socks5Udp::kMaxUdpHeaderBytes;
                std::vector<uint8_t> tmp;
                tmp.resize(cap > 0 ? (size_t)cap : 0);

                int rc = fpRecv(s, (char*)tmp.data(), (int)tmp.size(), flags);
                if (rc <= 0) return rc;

                Network::Socks5Udp::UnwrapResult unwrap{};
                if (!Network::Socks5Udp::Unwrap(tmp.data(), (size_t)rc, &unwrap)) {
                    WSASetLastError(WSAECONNRESET);
                    return SOCKET_ERROR;
                }

                const size_t payloadLen = unwrap.payloadLen;
                if ((int)payloadLen > len) {
                    memcpy(buf, unwrap.payload, (size_t)len);
                    WSASetLastError(WSAEMSGSIZE);
                    return SOCKET_ERROR;
                }

                memcpy(buf, unwrap.payload, payloadLen);
                Network::TrafficMonitor::Instance().LogRecv(s, buf, (int)payloadLen);
                return (int)payloadLen;
            }
        }
    }

    int result = fpRecv(s, buf, len, flags);
    if (result > 0) {
        Network::TrafficMonitor::Instance().LogRecv(s, buf, result);
    }
    return result;
}

int WSAAPI DetourWSASend(
    SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent, DWORD dwFlags,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
) {
    BeginOverlappedOperation(lpOverlapped);
    if (IsLocalBypassSocket(s)) {
        return fpWSASend(
            s, lpBuffers, dwBufferCount, lpNumberOfBytesSent,
            dwFlags, lpOverlapped, lpCompletionRoutine);
    }
    auto& config = Core::Config::Instance();

    // UDP/QUIC：connected UDP socket 可能走 WSASend，需要封装 SOCKS5 UDP 头
    if (config.proxy.port != 0 && GetEffectiveUdpAction(config) == Core::UdpAction::Proxy) {
        int soType = 0;
        if (TryGetSocketType(s, &soType) && soType == SOCK_DGRAM) {
            std::string host;
            uint16_t port = 0;
            if (TryGetUdpProxyDefaultTarget(s, &host, &port) && !host.empty() && port != 0) {
                sockaddr_storage local{};
                int localLen = (int)sizeof(local);
                const int family = (getsockname(s, (sockaddr*)&local, &localLen) == 0) ? (int)local.ss_family : AF_INET;

                if (!EnsureUdpProxyReady(s, family, host, port, true)) {
                    return SOCKET_ERROR;
                }

                std::vector<uint8_t> header;
                if (!Network::Socks5Udp::Wrap(host, port, nullptr, 0, &header)) {
                    WSASetLastError(WSAECONNREFUSED);
                    return SOCKET_ERROR;
                }

                const DWORD userBytes = (DWORD)SumWsabufBytes(lpBuffers, dwBufferCount);

                // 流量监控日志：记录用户 payload（不含 SOCKS5 UDP 头）
                if (lpBuffers && dwBufferCount > 0) {
                    Network::TrafficMonitor::Instance().LogSend(s, lpBuffers[0].buf, lpBuffers[0].len);
                }

                if (!lpOverlapped) {
                    std::vector<WSABUF> bufs;
                    bufs.reserve((size_t)dwBufferCount + 1);
                    WSABUF h{};
                    h.buf = (CHAR*)header.data();
                    h.len = (ULONG)header.size();
                    bufs.push_back(h);
                    for (DWORD i = 0; i < dwBufferCount; ++i) {
                        bufs.push_back(lpBuffers[i]);
                    }
                    int rc = fpWSASend(s, bufs.data(), (DWORD)bufs.size(), lpNumberOfBytesSent, dwFlags, NULL, NULL);
                    if (rc == 0 && lpNumberOfBytesSent) {
                        *lpNumberOfBytesSent = userBytes;
                    }
                    return rc;
                }

                auto ctx = std::make_shared<UdpOverlappedSendCtx>();
                ctx->sock = s;
                ctx->header = std::move(header);
                ctx->userBytes = userBytes;
                ctx->userBytesPtr = nullptr;
                ctx->userCompletion = lpCompletionRoutine;

                ctx->bufs.reserve((size_t)dwBufferCount + 1);
                WSABUF h{};
                h.buf = (CHAR*)ctx->header.data();
                h.len = (ULONG)ctx->header.size();
                ctx->bufs.push_back(h);
                for (DWORD i = 0; i < dwBufferCount; ++i) {
                    ctx->bufs.push_back(lpBuffers[i]);
                }

                {
                    std::lock_guard<std::mutex> lock(g_udpOvlMtx);
                    g_udpOvlRecv.erase(lpOverlapped);
                    g_udpOvlSend[lpOverlapped] = ctx;
                }

                const auto cb = lpCompletionRoutine ? UdpProxyCompletionRoutine : nullptr;
                int rc = fpWSASend(s, ctx->bufs.data(), (DWORD)ctx->bufs.size(), lpNumberOfBytesSent, dwFlags, lpOverlapped, cb);
                if (rc == SOCKET_ERROR) {
                    int err = WSAGetLastError();
                    if (err != WSA_IO_PENDING) {
                        DropUdpOverlappedContext(lpOverlapped);
                    } else {
                        if (lpNumberOfBytesSent) *lpNumberOfBytesSent = 0;
                    }
                    WSASetLastError(err);
                    return SOCKET_ERROR;
                }
                if (lpNumberOfBytesSent) *lpNumberOfBytesSent = userBytes;
                return rc;
            }
        }
    }

    // 流量监控日志 (记录第一个缓冲区)
    if (lpBuffers && dwBufferCount > 0) {
        Network::TrafficMonitor::Instance().LogSend(s, lpBuffers[0].buf, lpBuffers[0].len);
    }
    return fpWSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
}

int WSAAPI DetourWSARecv(
    SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
) {
    BeginOverlappedOperation(lpOverlapped);
    if (IsLocalBypassSocket(s)) {
        return fpWSARecv(
            s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd,
            lpFlags, lpOverlapped, lpCompletionRoutine);
    }
    auto& config = Core::Config::Instance();

    // UDP/QUIC：connected UDP socket 可能走 WSARecv，需要解封装 SOCKS5 UDP Reply
    if (config.proxy.port != 0 && GetEffectiveUdpAction(config) == Core::UdpAction::Proxy) {
        int soType = 0;
        if (TryGetSocketType(s, &soType) && soType == SOCK_DGRAM) {
            sockaddr_storage relay{};
            int relayLen = 0;
            if (TryGetUdpRelayAddr(s, &relay, &relayLen)) {
                const size_t userCap = SumWsabufBytes(lpBuffers, dwBufferCount);
                const size_t cap = userCap + Network::Socks5Udp::kMaxUdpHeaderBytes;

                if (!lpOverlapped) {
                    std::vector<uint8_t> tmp;
                    tmp.resize(cap);
                    WSABUF ib{};
                    ib.buf = (CHAR*)tmp.data();
                    ib.len = (ULONG)tmp.size();

                    DWORD bytes = 0;
                    sockaddr_storage source{}; int sourceLength=sizeof(source);
                    int rc = fpWSARecvFrom(s,&ib,1,&bytes,lpFlags,reinterpret_cast<sockaddr*>(&source),&sourceLength,NULL,NULL);
                    if (rc != 0) return rc;

                    Network::Socks5Udp::UnwrapResult unwrap{};
                    if (!DecodeUdpDatagram(s,tmp.data(),bytes,reinterpret_cast<sockaddr*>(&source),sourceLength,&unwrap)) {
                        WSASetLastError(WSAECONNRESET);
                        return SOCKET_ERROR;
                    }

                    const size_t copied = CopyBytesToWsabufs(unwrap.payload, unwrap.payloadLen, lpBuffers, dwBufferCount);
                    if (lpNumberOfBytesRecvd) *lpNumberOfBytesRecvd = (DWORD)copied;
                    if (copied < unwrap.payloadLen) {
                        WSASetLastError(WSAEMSGSIZE);
                        return SOCKET_ERROR;
                    }
                    if (lpBuffers && dwBufferCount > 0 && copied > 0) {
                        Network::TrafficMonitor::Instance().LogRecv(s, lpBuffers[0].buf, (int)copied);
                    }
                    return 0;
                }

                auto ctx = std::make_shared<UdpOverlappedRecvCtx>();
                ctx->sock = s;
                ctx->recvBuf.resize(cap);
                ctx->userBuffers.assign(lpBuffers, lpBuffers + dwBufferCount);
                ctx->userBufs = ctx->userBuffers.data();
                ctx->userBufCount = dwBufferCount;
                ctx->userBytesPtr = nullptr;
                ctx->userFlagsPtr = nullptr;
                ctx->userCompletion = lpCompletionRoutine;

                WSABUF ib{};
                ib.buf = (CHAR*)ctx->recvBuf.data();
                ib.len = (ULONG)ctx->recvBuf.size();

                {
                    std::lock_guard<std::mutex> lock(g_udpOvlMtx);
                    g_udpOvlSend.erase(lpOverlapped);
                    g_udpOvlRecv[lpOverlapped] = ctx;
                }

                const auto cb = lpCompletionRoutine ? UdpProxyCompletionRoutine : nullptr;
                int rc = fpWSARecvFrom(s,&ib,1,lpNumberOfBytesRecvd,lpFlags,
                    reinterpret_cast<sockaddr*>(&ctx->fromTmp),&ctx->fromTmpLen,lpOverlapped,cb);
                if (rc == SOCKET_ERROR) {
                    int err = WSAGetLastError();
                    if (err != WSA_IO_PENDING) {
                        DropUdpOverlappedContext(lpOverlapped);
                    } else {
                        if (lpNumberOfBytesRecvd) *lpNumberOfBytesRecvd = 0;
                    }
                    WSASetLastError(err);
                    return SOCKET_ERROR;
                }

                // 立即完成：立刻解封装并回填用户 buffers（避免上层读到 SOCKS5 UDP 头）
                {
                    DWORD userBytes=0; int error=0;
                    HandleUdpOverlappedCompletion(lpOverlapped,static_cast<DWORD>(lpOverlapped->InternalHigh),&userBytes,&error);
                    if(lpNumberOfBytesRecvd) *lpNumberOfBytesRecvd=userBytes;
                    if(error) { WSASetLastError(error); return SOCKET_ERROR; }
                }
                return rc;
            }
        }
    }

    int result = fpWSARecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine);
    // 注意：异步操作无法立即获取数据，仅记录同步接收
    if (result == 0 && lpNumberOfBytesRecvd && *lpNumberOfBytesRecvd > 0 && lpBuffers && dwBufferCount > 0) {
        Network::TrafficMonitor::Instance().LogRecv(s, lpBuffers[0].buf, *lpNumberOfBytesRecvd);
    }
    return result;
}

// ============= UDP 接收：recvfrom / WSARecvFrom Hook =============

int WSAAPI DetourRecvFrom(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen) {
    if (len < 0 || (!buf && len)) return fpRecvFrom(s,buf,len,flags,from,fromlen);
    if (!fpRecvFrom) {
        WSASetLastError(WSAEINVAL);
        return SOCKET_ERROR;
    }
    if (IsLocalBypassSocket(s)) {
        return fpRecvFrom(s, buf, len, flags, from, fromlen);
    }

    auto& config = Core::Config::Instance();
    if (config.proxy.port != 0 && GetEffectiveUdpAction(config) == Core::UdpAction::Proxy) {
        int soType = 0;
        if (TryGetSocketType(s, &soType) && soType == SOCK_DGRAM) {
            sockaddr_storage relay{};
            int relayLen = 0;
            if (TryGetUdpRelayAddr(s, &relay, &relayLen)) {
                const int cap = len + (int)Network::Socks5Udp::kMaxUdpHeaderBytes;
                std::vector<uint8_t> tmp;
                tmp.resize(cap > 0 ? (size_t)cap : 0);

                sockaddr_storage fromTmp{};
                int fromTmpLen = (int)sizeof(fromTmp);
                int rc = fpRecvFrom(s, (char*)tmp.data(), (int)tmp.size(), flags, (sockaddr*)&fromTmp, &fromTmpLen);
                if (rc <= 0) return rc;

                Network::Socks5Udp::UnwrapResult unwrap{};
                if (!DecodeUdpDatagram(s,tmp.data(),rc,reinterpret_cast<sockaddr*>(&fromTmp),fromTmpLen,&unwrap)) {
                    WSASetLastError(WSAECONNRESET);
                    return SOCKET_ERROR;
                }

                if (fromlen) {
                    if (unwrap.srcLen > 0) {
                        FillUserSockaddr(from, fromlen, unwrap.src, unwrap.srcLen);
                    } else {
                        *fromlen = 0;
                    }
                }

                if ((int)unwrap.payloadLen > len) {
                    memcpy(buf, unwrap.payload, (size_t)len);
                    WSASetLastError(WSAEMSGSIZE);
                    return SOCKET_ERROR;
                }

                memcpy(buf, unwrap.payload, unwrap.payloadLen);
                Network::TrafficMonitor::Instance().LogRecv(s, buf, (int)unwrap.payloadLen);
                return (int)unwrap.payloadLen;
            }
        }
    }

    return fpRecvFrom(s, buf, len, flags, from, fromlen);
}

int WSAAPI DetourWSARecvFrom(
    SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags,
    struct sockaddr* lpFrom, LPINT lpFromlen,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
) {
    BeginOverlappedOperation(lpOverlapped);
    if (!fpWSARecvFrom) {
        WSASetLastError(WSAEINVAL);
        return SOCKET_ERROR;
    }
    if (IsLocalBypassSocket(s)) {
        return fpWSARecvFrom(
            s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags,
            lpFrom, lpFromlen, lpOverlapped, lpCompletionRoutine);
    }

    auto& config = Core::Config::Instance();
    if (config.proxy.port != 0 && GetEffectiveUdpAction(config) == Core::UdpAction::Proxy) {
        int soType = 0;
        if (TryGetSocketType(s, &soType) && soType == SOCK_DGRAM) {
            sockaddr_storage relay{};
            int relayLen = 0;
            if (TryGetUdpRelayAddr(s, &relay, &relayLen)) {
                const size_t userCap = SumWsabufBytes(lpBuffers, dwBufferCount);
                const size_t cap = userCap + Network::Socks5Udp::kMaxUdpHeaderBytes;

                if (!lpOverlapped) {
                    std::vector<uint8_t> tmp;
                    tmp.resize(cap);
                    WSABUF ib{};
                    ib.buf = (CHAR*)tmp.data();
                    ib.len = (ULONG)tmp.size();

                    sockaddr_storage fromTmp{};
                    int fromTmpLen = (int)sizeof(fromTmp);
                    DWORD bytes = 0;
                    int rc = fpWSARecvFrom(s, &ib, 1, &bytes, lpFlags, (sockaddr*)&fromTmp, &fromTmpLen, NULL, NULL);
                    if (rc != 0) return rc;

                    Network::Socks5Udp::UnwrapResult unwrap{};
                    if (!DecodeUdpDatagram(s,tmp.data(),bytes,reinterpret_cast<sockaddr*>(&fromTmp),fromTmpLen,&unwrap)) {
                        WSASetLastError(WSAECONNRESET);
                        return SOCKET_ERROR;
                    }

                    const size_t copied = CopyBytesToWsabufs(unwrap.payload, unwrap.payloadLen, lpBuffers, dwBufferCount);
                    if (lpNumberOfBytesRecvd) *lpNumberOfBytesRecvd = (DWORD)copied;
                    if (lpFromlen) {
                        if (unwrap.srcLen > 0) {
                            FillUserSockaddr(lpFrom, lpFromlen, unwrap.src, unwrap.srcLen);
                        } else {
                            *lpFromlen = 0;
                        }
                    }
                    if (copied < unwrap.payloadLen) {
                        WSASetLastError(WSAEMSGSIZE);
                        return SOCKET_ERROR;
                    }
                    if (lpBuffers && dwBufferCount > 0 && copied > 0) {
                        Network::TrafficMonitor::Instance().LogRecv(s, lpBuffers[0].buf, (int)copied);
                    }
                    return 0;
                }

                auto ctx = std::make_shared<UdpOverlappedRecvCtx>();
                ctx->sock = s;
                ctx->recvBuf.resize(cap);
                ctx->userBuffers.assign(lpBuffers, lpBuffers + dwBufferCount);
                ctx->userBufs = ctx->userBuffers.data();
                ctx->userBufCount = dwBufferCount;
                ctx->userBytesPtr = nullptr;
                ctx->userFlagsPtr = nullptr;
                ctx->userFrom = lpFrom;
                ctx->userFromLen = lpFromlen;
                ctx->userCompletion = lpCompletionRoutine;

                WSABUF ib{};
                ib.buf = (CHAR*)ctx->recvBuf.data();
                ib.len = (ULONG)ctx->recvBuf.size();

                {
                    std::lock_guard<std::mutex> lock(g_udpOvlMtx);
                    g_udpOvlSend.erase(lpOverlapped);
                    g_udpOvlRecv[lpOverlapped] = ctx;
                }

                const auto cb = lpCompletionRoutine ? UdpProxyCompletionRoutine : nullptr;
                int rc = fpWSARecvFrom(s, &ib, 1, lpNumberOfBytesRecvd, lpFlags,
                                       (sockaddr*)&ctx->fromTmp, &ctx->fromTmpLen,
                                       lpOverlapped, cb);
                if (rc == SOCKET_ERROR) {
                    int err = WSAGetLastError();
                    if (err != WSA_IO_PENDING) {
                        DropUdpOverlappedContext(lpOverlapped);
                    } else {
                        if (lpNumberOfBytesRecvd) *lpNumberOfBytesRecvd = 0;
                    }
                    WSASetLastError(err);
                    return SOCKET_ERROR;
                }

                // 立即完成：立刻解封装并回填用户 buffers / from
                {
                    DWORD userBytes=0; int error=0;
                    HandleUdpOverlappedCompletion(lpOverlapped,static_cast<DWORD>(lpOverlapped->InternalHigh),&userBytes,&error);
                    if(lpNumberOfBytesRecvd) *lpNumberOfBytesRecvd=userBytes;
                    if(error) { WSASetLastError(error); return SOCKET_ERROR; }
                }
                return rc;
            }
        }
    }

    return fpWSARecvFrom(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpFrom, lpFromlen, lpOverlapped, lpCompletionRoutine);
}

// ============= UDP 强阻断: sendto / WSASendTo Hook =============

int WSAAPI DetourSendTo(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen) {
    if (len < 0 || (!buf && len)) return fpSendTo(s,buf,len,flags,to,tolen);
    if (!fpSendTo) {
        WSASetLastError(WSAEINVAL);
        return SOCKET_ERROR;
    }
    if (to) {
        const bool isLocalTarget = Network::IsLocalSockaddr(to, tolen);
        // A local datagram does not change an unconnected socket's lifetime
        // policy or destroy an association used by other destinations.
        if(isLocalTarget && !IsSocketConnected(s)) return fpSendTo(s,buf,len,flags,to,tolen);
        SetLocalBypassSocket(s, isLocalTarget);
        if (isLocalTarget) {
            CleanupUdpProxyContext(s);
            ForgetSocketTarget(s);
            return fpSendTo(s, buf, len, flags, to, tolen);
        }
    } else if (IsLocalBypassSocket(s)) {
        return fpSendTo(s, buf, len, flags, to, tolen);
    }

    auto& config = Core::Config::Instance();
    if (config.proxy.port != 0) {
        int soType = 0;
        if (TryGetSocketType(s, &soType) && soType == SOCK_DGRAM) {
            sockaddr_storage peer{};
            int peerLen = (int)sizeof(peer);
            const sockaddr* dst = to;
            if (!dst && !TryGetUdpProxyDefaultTarget(s, nullptr, nullptr)) {
                if (getpeername(s, (sockaddr*)&peer, &peerLen) == 0) {
                    dst = (sockaddr*)&peer;
                }
            }

            if (IsBlockedUdpV6(dst)) { WSASetLastError(WSAEACCES); return SOCKET_ERROR; }
            const Core::UdpAction udpAction = GetEffectiveUdpAction(config);
            if (udpAction == Core::UdpAction::Block) {
                uint16_t dstPort = 0;
                const bool hasPort = TryGetSockaddrPort(dst, &dstPort);
                // 例外判断统一收敛到 IsUdpBlockExempt（loopback / UDP53 / 局域网等 direct 路由规则）
                const bool allowUdp = IsUdpBlockExempt(config, dst, hasPort, dstPort);
                if (!allowUdp) {
                    const int err = WSAEACCES;
                    if (ShouldLogUdpBlock()) {
                        const std::string dstStr = dst ? SockaddrToString(dst) : std::string("(未知)");
                        Core::Logger::Warn("sendto: 已阻止 UDP 发送(策略: " + GetUdpPolicyLabel(config) + "), sock=" + std::to_string((unsigned long long)s) +
                                           ", dst=" + dstStr +
                                           (hasPort ? (", port=" + std::to_string(dstPort)) : std::string("")) +
                                           ", WSA错误码=" + std::to_string(err));
                    }
                    WSASetLastError(err);
                    return SOCKET_ERROR;
                }
                return DirectUdpSendTo(s,buf,len,flags,to,tolen);
            }

            // 有效策略为 proxy：封装为 SOCKS5 UDP 报文并发给 relay
            if (udpAction == Core::UdpAction::Proxy) {
                std::string host;
                uint16_t port = 0;
                int family = AF_INET;
                if (dst) {
                    family = (int)dst->sa_family;
                    if (!ResolveOriginalTarget(dst, &host, &port) || host.empty() || port == 0) {
                        WSASetLastError(WSAEINVAL);
                        return SOCKET_ERROR;
                    }
                    if (!ShouldProxyUdpByRule(dst, host, port)) {
                        return DirectUdpSendTo(s,buf,len,flags,to,tolen);
                    }
                } else {
                    // sendto(to=null) = 发送到“已连接目标”。若该 socket 已处于 UDP 代理模式，使用保存的 default target。
                    if (!TryGetUdpProxyDefaultTarget(s, &host, &port) || host.empty() || port == 0) {
                        WSASetLastError(WSAEDESTADDRREQ);
                        return SOCKET_ERROR;
                    }
                    sockaddr_storage local{};
                    int localLen = (int)sizeof(local);
                    if (getsockname(s, (sockaddr*)&local, &localLen) == 0) {
                        family = (int)local.ss_family;
                    }
                }

                sockaddr_storage relayDestination{}; int relayDestinationLength=0;
                if (!PrepareUdpDatagramRelay(s,family,host,port,&relayDestination,&relayDestinationLength)) {
                    if (config.rules.udp_fallback == "direct" && dst) {
                        if (ShouldLogUdpProxyFail()) {
                            const int err = WSAGetLastError();
                            Core::Logger::Warn("sendto: UDP 代理失败，回退为 direct, sock=" + std::to_string((unsigned long long)s) +
                                               ", target=" + host + ":" + std::to_string(port) +
                                               ", WSA错误码=" + std::to_string(err));
                        }
                        CleanupUdpProxyContext(s);
                        return DirectUdpSendTo(s,buf,len,flags,to,tolen);
                    }
                    return SOCKET_ERROR;
                }
                RememberSocketTarget(s, host, port);

                std::vector<uint8_t> packet;
                if (!Network::Socks5Udp::Wrap(host, port, (const uint8_t*)buf, (size_t)len, &packet)) {
                    if (config.rules.udp_fallback == "direct" && dst) {
                        if (ShouldLogUdpProxyFail()) {
                            Core::Logger::Warn("sendto: UDP 封装失败，回退为 direct, sock=" + std::to_string((unsigned long long)s) +
                                               ", target=" + host + ":" + std::to_string(port));
                        }
                        CleanupUdpProxyContext(s);
                        return DirectUdpSendTo(s,buf,len,flags,to,tolen);
                    }
                    WSASetLastError(WSAECONNREFUSED);
                    return SOCKET_ERROR;
                }

                int sent=fpSendTo(s,reinterpret_cast<const char*>(packet.data()),static_cast<int>(packet.size()),flags,
                    reinterpret_cast<sockaddr*>(&relayDestination),relayDestinationLength);
                if (sent == SOCKET_ERROR) {
                    return SOCKET_ERROR;
                }
                return len; // 用户视角：仅 payload 长度
            }
        }
    }

    return DirectUdpSendTo(s,buf,len,flags,to,tolen);
}

int WSAAPI DetourWSASendTo(
    SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent, DWORD dwFlags,
    const struct sockaddr* lpTo, int iToLen,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
) {
    BeginOverlappedOperation(lpOverlapped);
    if (!fpWSASendTo) {
        WSASetLastError(WSAEINVAL);
        return SOCKET_ERROR;
    }
    if (lpTo) {
        const bool isLocalTarget = Network::IsLocalSockaddr(lpTo, iToLen);
        if(isLocalTarget && !IsSocketConnected(s))
            return fpWSASendTo(s,lpBuffers,dwBufferCount,lpNumberOfBytesSent,dwFlags,lpTo,iToLen,lpOverlapped,lpCompletionRoutine);
        SetLocalBypassSocket(s, isLocalTarget);
        if (isLocalTarget) {
            CleanupUdpProxyContext(s);
            ForgetSocketTarget(s);
            return fpWSASendTo(
                s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags,
                lpTo, iToLen, lpOverlapped, lpCompletionRoutine);
        }
    } else if (IsLocalBypassSocket(s)) {
        return fpWSASendTo(
            s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags,
            lpTo, iToLen, lpOverlapped, lpCompletionRoutine);
    }

    auto& config = Core::Config::Instance();
    if (config.proxy.port != 0) {
        int soType = 0;
        if (TryGetSocketType(s, &soType) && soType == SOCK_DGRAM) {
            sockaddr_storage peer{};
            int peerLen = (int)sizeof(peer);
            const sockaddr* dst = lpTo;
            if (!dst && !TryGetUdpProxyDefaultTarget(s, nullptr, nullptr)) {
                if (getpeername(s, (sockaddr*)&peer, &peerLen) == 0) {
                    dst = (sockaddr*)&peer;
                }
            }

            if (IsBlockedUdpV6(dst)) { WSASetLastError(WSAEACCES); return SOCKET_ERROR; }
            const Core::UdpAction udpAction = GetEffectiveUdpAction(config);
            if (udpAction == Core::UdpAction::Block) {
                uint16_t dstPort = 0;
                const bool hasPort = TryGetSockaddrPort(dst, &dstPort);
                // 例外判断统一收敛到 IsUdpBlockExempt（loopback / UDP53 / 局域网等 direct 路由规则）
                const bool allowUdp = IsUdpBlockExempt(config, dst, hasPort, dstPort);
                if (!allowUdp) {
                    const int err = WSAEACCES;
                    if (lpNumberOfBytesSent) {
                        *lpNumberOfBytesSent = 0;
                    }
                    if (ShouldLogUdpBlock()) {
                        const std::string dstStr = dst ? SockaddrToString(dst) : std::string("(未知)");
                        Core::Logger::Warn("WSASendTo: 已阻止 UDP 发送(策略: " + GetUdpPolicyLabel(config) + "), sock=" + std::to_string((unsigned long long)s) +
                                           ", dst=" + dstStr +
                                           (hasPort ? (", port=" + std::to_string(dstPort)) : std::string("")) +
                                           ", WSA错误码=" + std::to_string(err));
                    }
                    WSASetLastError(err);
                    return SOCKET_ERROR;
                }
                return DirectUdpWSASendTo(s,lpBuffers,dwBufferCount,lpNumberOfBytesSent,dwFlags,lpTo,iToLen,lpOverlapped,lpCompletionRoutine);
            }

            // 有效策略为 proxy：封装为 SOCKS5 UDP 报文并发给 relay
            if (udpAction == Core::UdpAction::Proxy) {
                std::string host;
                uint16_t port = 0;
                int family = AF_INET;
                if (dst) {
                    family = (int)dst->sa_family;
                    if (!ResolveOriginalTarget(dst, &host, &port) || host.empty() || port == 0) {
                        WSASetLastError(WSAEINVAL);
                        return SOCKET_ERROR;
                    }
                    if (!ShouldProxyUdpByRule(dst, host, port)) {
                        return DirectUdpWSASendTo(s,lpBuffers,dwBufferCount,lpNumberOfBytesSent,dwFlags,lpTo,iToLen,lpOverlapped,lpCompletionRoutine);
                    }
                } else {
                    if (!TryGetUdpProxyDefaultTarget(s, &host, &port) || host.empty() || port == 0) {
                        WSASetLastError(WSAEDESTADDRREQ);
                        return SOCKET_ERROR;
                    }
                    sockaddr_storage local{};
                    int localLen = (int)sizeof(local);
                    if (getsockname(s, (sockaddr*)&local, &localLen) == 0) {
                        family = (int)local.ss_family;
                    }
                }

                sockaddr_storage relayDestination{}; int relayDestinationLength=0;
                if (!PrepareUdpDatagramRelay(s,family,host,port,&relayDestination,&relayDestinationLength)) {
                    if (config.rules.udp_fallback == "direct" && dst) {
                        if (ShouldLogUdpProxyFail()) {
                            const int err = WSAGetLastError();
                            Core::Logger::Warn("WSASendTo: UDP 代理失败，回退为 direct, sock=" + std::to_string((unsigned long long)s) +
                                               ", target=" + host + ":" + std::to_string(port) +
                                               ", WSA错误码=" + std::to_string(err));
                        }
                        CleanupUdpProxyContext(s);
                        return DirectUdpWSASendTo(s,lpBuffers,dwBufferCount,lpNumberOfBytesSent,dwFlags,lpTo,iToLen,lpOverlapped,lpCompletionRoutine);
                    }
                    return SOCKET_ERROR;
                }
                RememberSocketTarget(s, host, port);

                std::vector<uint8_t> header;
                if (!Network::Socks5Udp::Wrap(host, port, nullptr, 0, &header)) {
                    if (config.rules.udp_fallback == "direct" && dst) {
                        if (ShouldLogUdpProxyFail()) {
                            Core::Logger::Warn("WSASendTo: UDP 封装失败，回退为 direct, sock=" + std::to_string((unsigned long long)s) +
                                               ", target=" + host + ":" + std::to_string(port));
                        }
                        CleanupUdpProxyContext(s);
                        return DirectUdpWSASendTo(s,lpBuffers,dwBufferCount,lpNumberOfBytesSent,dwFlags,lpTo,iToLen,lpOverlapped,lpCompletionRoutine);
                    }
                    WSASetLastError(WSAECONNREFUSED);
                    return SOCKET_ERROR;
                }

                const DWORD userBytes = (DWORD)SumWsabufBytes(lpBuffers, dwBufferCount);

                if (!lpOverlapped) {
                    // 同步：拼接 WSABUF 头 + 用户 payload
                    std::vector<WSABUF> bufs;
                    bufs.reserve((size_t)dwBufferCount + 1);
                    WSABUF h{};
                    h.buf = (CHAR*)header.data();
                    h.len = (ULONG)header.size();
                    bufs.push_back(h);
                    for (DWORD i = 0; i < dwBufferCount; ++i) {
                        bufs.push_back(lpBuffers[i]);
                    }
                    int rc=fpWSASendTo(s,bufs.data(),static_cast<DWORD>(bufs.size()),lpNumberOfBytesSent,dwFlags,
                        reinterpret_cast<sockaddr*>(&relayDestination),relayDestinationLength,NULL,NULL);
                    if (rc == 0 && lpNumberOfBytesSent) {
                        *lpNumberOfBytesSent = userBytes;
                    }
                    return rc;
                }

                // Overlapped：保存上下文，等待完成时修正 bytesTransferred
                auto ctx = std::make_shared<UdpOverlappedSendCtx>();
                ctx->sock = s;
                ctx->header = std::move(header);
                ctx->userBytes = userBytes;
                ctx->userBytesPtr = nullptr;
                ctx->userCompletion = lpCompletionRoutine;

                ctx->bufs.reserve((size_t)dwBufferCount + 1);
                WSABUF h{};
                h.buf = (CHAR*)ctx->header.data();
                h.len = (ULONG)ctx->header.size();
                ctx->bufs.push_back(h);
                for (DWORD i = 0; i < dwBufferCount; ++i) {
                    ctx->bufs.push_back(lpBuffers[i]);
                }

                {
                    std::lock_guard<std::mutex> lock(g_udpOvlMtx);
                    g_udpOvlRecv.erase(lpOverlapped);
                    g_udpOvlSend[lpOverlapped] = ctx;
                }

                // 走 WSASend（socket 已 connect 到 relay）
                const auto cb = lpCompletionRoutine ? UdpProxyCompletionRoutine : nullptr;
                int rc=fpWSASendTo(s,ctx->bufs.data(),static_cast<DWORD>(ctx->bufs.size()),lpNumberOfBytesSent,dwFlags,
                    reinterpret_cast<sockaddr*>(&relayDestination),relayDestinationLength,lpOverlapped,cb);

                if (rc == SOCKET_ERROR) {
                    int err = WSAGetLastError();
                    if (err != WSA_IO_PENDING) {
                        DropUdpOverlappedContext(lpOverlapped);
                    } else {
                        // IO_PENDING：立即把 lpNumberOfBytesSent 置 0，符合调用方预期
                        if (lpNumberOfBytesSent) *lpNumberOfBytesSent = 0;
                    }
                    WSASetLastError(err);
                    return SOCKET_ERROR;
                }

                // 立即完成：修正 bytesSent（completionRoutine 可能稍后才触发）
                if (lpNumberOfBytesSent) *lpNumberOfBytesSent = userBytes;
                return rc;
            }
        }
    }

    return DirectUdpWSASendTo(s,lpBuffers,dwBufferCount,lpNumberOfBytesSent,dwFlags,lpTo,iToLen,lpOverlapped,lpCompletionRoutine);
}

// ============= Hook 管理 =============


namespace Hooks {
    bool Install(bool network) {
        // The imports pin these system modules; explicitly load WinHTTP before hooks.
        if (!LoadLibraryExW(L"winhttp.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32)) return false;
        if (MH_Initialize() != MH_OK) return false;
        bool ok = true;
        auto hook = [&](const wchar_t* module, const char* name, void* detour, void** original) {
            MH_STATUS result = MH_CreateHookApi(module, name, detour, original);
            if (result != MH_OK) {
                Core::Logger::Error(std::string("Cannot hook ") + name + ": " + MH_StatusToString(result));
                ok = false;
            }
        };
#define CP_HOOK(module, name, detour, original) hook(module, name, reinterpret_cast<void*>(detour), reinterpret_cast<void**>(&(original)))
        if (network) {
            CP_HOOK(L"ws2_32.dll", "ioctlsocket", DetourIoctlSocket, fpIoctlSocket);
            CP_HOOK(L"ws2_32.dll", "WSAEventSelect", DetourWSAEventSelect, fpWSAEventSelect);
            CP_HOOK(L"ws2_32.dll", "WSAAsyncSelect", DetourWSAAsyncSelect, fpWSAAsyncSelect);
            CP_HOOK(L"ws2_32.dll", "socket", DetourSocket, fpSocket);
            CP_HOOK(L"ws2_32.dll", "WSASocketA", DetourWSASocketA, fpWSASocketA);
            CP_HOOK(L"ws2_32.dll", "WSASocketW", DetourWSASocketW, fpWSASocketW);
            CP_HOOK(L"ws2_32.dll", "connect", DetourConnect, fpConnect);
            CP_HOOK(L"ws2_32.dll", "WSAConnect", DetourWSAConnect, fpWSAConnect);
            CP_HOOK(L"ws2_32.dll", "WSAIoctl", DetourWSAIoctl, fpWSAIoctl);
            CP_HOOK(L"ws2_32.dll", "WSAConnectByNameA", DetourWSAConnectByNameA, fpWSAConnectByNameA);
            CP_HOOK(L"ws2_32.dll", "WSAConnectByNameW", DetourWSAConnectByNameW, fpWSAConnectByNameW);
            CP_HOOK(L"ws2_32.dll", "getaddrinfo", DetourGetAddrInfo, fpGetAddrInfo);
            CP_HOOK(L"ws2_32.dll", "GetAddrInfoW", DetourGetAddrInfoW, fpGetAddrInfoW);
            CP_HOOK(L"ws2_32.dll", "GetAddrInfoExW", DetourGetAddrInfoExW, fpGetAddrInfoExW);
            CP_HOOK(L"ws2_32.dll", "gethostbyname", DetourGetHostByName, fpGetHostByName);
            CP_HOOK(L"ws2_32.dll", "send", DetourSend, fpSend);
            CP_HOOK(L"ws2_32.dll", "recv", DetourRecv, fpRecv);
            CP_HOOK(L"ws2_32.dll", "sendto", DetourSendTo, fpSendTo);
            CP_HOOK(L"ws2_32.dll", "recvfrom", DetourRecvFrom, fpRecvFrom);
            CP_HOOK(L"ws2_32.dll", "WSASend", DetourWSASend, fpWSASend);
            CP_HOOK(L"ws2_32.dll", "WSARecv", DetourWSARecv, fpWSARecv);
            CP_HOOK(L"ws2_32.dll", "WSASendTo", DetourWSASendTo, fpWSASendTo);
            CP_HOOK(L"ws2_32.dll", "WSARecvFrom", DetourWSARecvFrom, fpWSARecvFrom);
            CP_HOOK(L"ws2_32.dll", "WSAGetOverlappedResult", DetourWSAGetOverlappedResult, fpWSAGetOverlappedResult);
            CP_HOOK(L"ws2_32.dll", "closesocket", DetourCloseSocket, fpCloseSocket);
            CP_HOOK(L"ws2_32.dll", "shutdown", DetourShutdown, fpShutdown);
            CP_HOOK(L"kernel32.dll", "GetQueuedCompletionStatus", DetourGetQueuedCompletionStatus, fpGetQueuedCompletionStatus);
            CP_HOOK(L"kernel32.dll", "GetQueuedCompletionStatusEx", DetourGetQueuedCompletionStatusEx, fpGetQueuedCompletionStatusEx);

            const auto& proxy = Core::Config::Instance().proxy;
            if (proxy.ignore_system_proxy && proxy.port > 0) {
                CP_HOOK(L"winhttp.dll", "WinHttpGetIEProxyConfigForCurrentUser", DetourWinHttpIEProxy, fpWinHttpIEProxy);
                CP_HOOK(L"winhttp.dll", "WinHttpGetProxyForUrl", DetourWinHttpProxyForUrl, fpWinHttpProxyForUrl);
            }
        }
        if (Core::Config::Instance().childInjection) {
            CP_HOOK(L"kernel32.dll", "CreateProcessW", DetourCreateProcessW, fpCreateProcessW);
            CP_HOOK(L"kernel32.dll", "CreateProcessA", DetourCreateProcessA, fpCreateProcessA);
        }
#undef CP_HOOK
        if (ok && MH_EnableHook(MH_ALL_HOOKS) == MH_OK) return true;
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
        Core::Logger::Error("Hook installation rolled back");
        return false;
    }
}
