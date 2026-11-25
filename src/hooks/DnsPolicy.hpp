#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mutex>
#include <set>
#include "../core/Config.hpp"
#include "../network/FakeIP.hpp"
#include "../network/LocalTargetPolicy.hpp"
#include "../network/SocketIo.hpp"

namespace Hooks {
inline bool ShouldFakeDns(const std::string& node, uint16_t port, int family, int flags, int socketType) {
    const auto& config = Core::Config::Instance();
    if (Network::SocketIo::internalDnsDepth || !config.fakeIp.enabled || config.proxy.port <= 0 || node.empty() ||
        (flags & (AI_NUMERICHOST | AI_PASSIVE)) ||
        (family != AF_UNSPEC && family != AF_INET && family != AF_INET6) ||
        Network::IsLoopbackHost(node) || node == "..localmachine") return false;
    in_addr v4{}; in6_addr v6{};
    if (inet_pton(AF_INET, node.c_str(), &v4) == 1 || inet_pton(AF_INET6, node.c_str(), &v6) == 1) return false;
    char hostname[256]{};
    if (gethostname(hostname, sizeof(hostname)) == 0 &&
        Core::ProxyRules::ToLower(node) == Core::ProxyRules::ToLower(hostname)) return false;
    if (Core::ProxyRules::ToLower(node) == Core::ProxyRules::ToLower(config.proxy.host)) return false;
    // Keep the name until connect-time routing, including domain-only direct
    // rules. ResolveDirectTarget resolves the real address only after that rule
    // has been selected; returning a real IP here would lose its identity.
    (void)port; (void)socketType;
    return true;
}
// Stable backing for native async providers: bounded by two spellings per FakeIP.
// No callback, event, cancellation-handle or allocator emulation is necessary.
inline const wchar_t* StableNumericName(uint32_t address, int family) {
    auto text = Network::FakeIP::IpToString(address);
    if (family == AF_INET6) text = "::ffff:" + text;
    std::wstring value(text.begin(), text.end());
    static std::mutex mutex;
    static std::set<std::wstring> names;
    std::lock_guard<std::mutex> guard(mutex);
    return names.insert(std::move(value)).first->c_str();
}
}
