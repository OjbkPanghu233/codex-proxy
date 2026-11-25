// Derived from antigravity-proxy (BSD-2-Clause); see LICENSE.txt / AUTHORS.txt.
#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include <cctype>
#include <cstring>
#include <string>
#include <string_view>
#include <mutex>
#include <vector>

namespace Network {

inline bool IsIpv4LoopbackAddress(const in_addr& address) {
    return (ntohl(address.s_addr) >> 24) == 127;
}

inline bool IsIpv6LoopbackAddress(const in6_addr& address) {
    if (IN6_IS_ADDR_LOOPBACK(&address)) return true;
    if (!IN6_IS_ADDR_V4MAPPED(&address)) return false;

    in_addr mapped{};
    const auto* raw = reinterpret_cast<const unsigned char*>(&address);
    std::memcpy(&mapped, raw + 12, sizeof(mapped));
    return IsIpv4LoopbackAddress(mapped);
}

inline std::string NormalizeLoopbackHost(std::string_view host) {
    std::string normalized(host);
    for (char& ch : normalized) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    while (!normalized.empty() && normalized.back() == '.') {
        normalized.pop_back();
    }
    if (normalized.size() >= 2 && normalized.front() == '[' && normalized.back() == ']') {
        normalized = normalized.substr(1, normalized.size() - 2);
    }
    return normalized;
}

inline bool IsLoopbackHost(std::string_view host) {
    const std::string normalized = NormalizeLoopbackHost(host);
    if (normalized == "localhost") return true;

    in_addr address4{};
    if (inet_pton(AF_INET, normalized.c_str(), &address4) == 1) {
        return IsIpv4LoopbackAddress(address4);
    }

    in6_addr address6{};
    if (inet_pton(AF_INET6, normalized.c_str(), &address6) == 1) {
        return IsIpv6LoopbackAddress(address6);
    }
    return false;
}

inline bool IsLoopbackSockaddr(const sockaddr* address, int addressLength) {
    if (!address || addressLength < static_cast<int>(sizeof(address->sa_family))) return false;

    if (address->sa_family == AF_INET) {
        if (addressLength < static_cast<int>(sizeof(sockaddr_in))) return false;
        return IsIpv4LoopbackAddress(reinterpret_cast<const sockaddr_in*>(address)->sin_addr);
    }
    if (address->sa_family == AF_INET6) {
        if (addressLength < static_cast<int>(sizeof(sockaddr_in6))) return false;
        return IsIpv6LoopbackAddress(reinterpret_cast<const sockaddr_in6*>(address)->sin6_addr);
    }
    return false;
}

// Also bypass addresses assigned to this machine, regardless of routing overrides.
// Refresh after interface changes without adding a table query to every send/recv.
inline bool IsLocalSockaddr(const sockaddr* address, int length) {
    if (IsLoopbackSockaddr(address, length)) return true;
    if (!address || length < static_cast<int>(sizeof(sockaddr))) return false;
    if ((address->sa_family == AF_INET && length < sizeof(sockaddr_in)) ||
        (address->sa_family == AF_INET6 && length < sizeof(sockaddr_in6))) return false;
    static std::mutex mutex;
    static ULONGLONG updated = 0;
    static std::vector<SOCKADDR_INET> addresses;
    std::lock_guard<std::mutex> guard(mutex);
    if (updated == 0 || GetTickCount64() - updated > 30000) {
        PMIB_UNICASTIPADDRESS_TABLE table = nullptr;
        if (GetUnicastIpAddressTable(AF_UNSPEC, &table) == NO_ERROR) {
            addresses.clear();
            for (ULONG i = 0; i < table->NumEntries; ++i) addresses.push_back(table->Table[i].Address);
            FreeMibTable(table);
        }
        updated = GetTickCount64();
    }
    in_addr mapped{};
    if (address->sa_family == AF_INET6 && IN6_IS_ADDR_V4MAPPED(&reinterpret_cast<const sockaddr_in6*>(address)->sin6_addr)) {
        memcpy(&mapped, reinterpret_cast<const sockaddr_in6*>(address)->sin6_addr.u.Byte + 12, 4);
    }
    for (const auto& local : addresses) {
        if (local.si_family == AF_INET) {
            if (address->sa_family == AF_INET && local.Ipv4.sin_addr.s_addr == reinterpret_cast<const sockaddr_in*>(address)->sin_addr.s_addr) return true;
            if (mapped.s_addr && mapped.s_addr == local.Ipv4.sin_addr.s_addr) return true;
        } else if (local.si_family == AF_INET6 && address->sa_family == AF_INET6) {
            const auto& candidate = *reinterpret_cast<const sockaddr_in6*>(address);
            if (!memcmp(&local.Ipv6.sin6_addr, &candidate.sin6_addr, sizeof(in6_addr)) &&
                (!candidate.sin6_scope_id || candidate.sin6_scope_id == local.Ipv6.sin6_scope_id)) return true;
        }
    }
    return false;
}

}  // namespace Network
