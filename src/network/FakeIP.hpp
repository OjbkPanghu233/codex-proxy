// Derived from antigravity-proxy (BSD-2-Clause); see LICENSE.txt / AUTHORS.txt.
#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <mutex>
#include <string>
#include <unordered_map>
#include "../core/Config.hpp"

namespace Network {
// A shared cursor prevents independent process pools assigning one IP to different
// domains. Every read validates the shared slot, including cached allocations.
class FakeIP {
    struct Entry { char domain[256]; };
    struct Header { uint32_t magic, base, mask, cursor; };
    uint32_t base_ = 0, mask_ = 0, capacity_ = 0;
    HANDLE mapping_ = nullptr, mutex_ = nullptr;
    Header* header_ = nullptr;
    Entry* entries_ = nullptr;
    std::mutex localMutex_;
    std::unordered_map<std::string, uint32_t> cache_;
    std::once_flag once_;
    bool Lock() {
        if (!mutex_ || !header_) return false;
        auto wait = WaitForSingleObject(mutex_, 5000);
        return wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED;
    }
    void Initialize() {
        Core::ProxyRules::CidrRuleV4 cidr{};
        if (!Core::ProxyRules::ParseCidrV4(Core::Config::Instance().fakeIp.cidr, &cidr) ||
            cidr.mask < 0xfffe0000u || cidr.mask > 0xfffffffcu) return;
        base_ = cidr.network; mask_ = cidr.mask; capacity_ = ~mask_ - 1;
        // Separate unrelated configurations while sharing across an injected tree.
        uint64_t hash = 14695981039346656037ull;
        auto key = Core::Config::Instance().loadedPath.wstring() + std::to_wstring(base_) + L"/" + std::to_wstring(mask_);
        for (wchar_t ch : key) { hash ^= static_cast<uint16_t>(towlower(ch)); hash *= 1099511628211ull; }
        std::wstring name = L"Local\\CodexProxy_FakeIP_v2_" + std::to_wstring(hash);
        mutex_ = CreateMutexW(nullptr, FALSE, (name + L"_Mutex").c_str());
        if (!mutex_) return;
        auto wait = WaitForSingleObject(mutex_, 5000);
        if (wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED) return;
        DWORD bytes = static_cast<DWORD>(sizeof(Header) + capacity_ * sizeof(Entry));
        mapping_ = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, bytes, name.c_str());
        DWORD error = GetLastError();
        if (mapping_) header_ = static_cast<Header*>(MapViewOfFile(mapping_, FILE_MAP_ALL_ACCESS, 0, 0, bytes));
        if (header_) {
            entries_ = reinterpret_cast<Entry*>(header_ + 1);
            if (error != ERROR_ALREADY_EXISTS || header_->magic != 0x43504632 || header_->base != base_ || header_->mask != mask_) {
                ZeroMemory(header_, bytes);
                header_->base = base_; header_->mask = mask_;
                header_->magic = 0x43504632;
            }
        }
        ReleaseMutex(mutex_);
    }
public:
    static FakeIP& Instance() { static FakeIP f; f.Init(); return f; }
    void Init() { std::call_once(once_, [this] { Initialize(); }); }
    bool IsFakeIP(uint32_t networkOrder) {
        Init(); return mask_ && ((ntohl(networkOrder) & mask_) == base_);
    }
    uint32_t Alloc(std::string domain) {
        Init();
        domain = Core::ProxyRules::ToLower(domain);
        if (!domain.empty() && domain.back() == '.') domain.pop_back();
        if (domain.empty() || domain.size() > 255 || domain.find('\0') != std::string::npos) return 0;
        std::lock_guard<std::mutex> guard(localMutex_);
        if (!Lock()) return 0;
        auto cached = cache_.find(domain);
        if (cached != cache_.end() && domain == entries_[cached->second].domain) {
            auto ip = htonl(base_ + cached->second + 1);
            ReleaseMutex(mutex_); return ip;
        }
        uint32_t slot = header_->cursor++ % capacity_;
        entries_[slot] = {};
        memcpy(entries_[slot].domain, domain.data(), domain.size());
        if (cache_.size() >= capacity_) cache_.clear();
        cache_[domain] = slot;
        ReleaseMutex(mutex_);
        return htonl(base_ + slot + 1);
    }
    std::string GetDomain(uint32_t networkOrder) {
        Init();
        uint32_t offset = ntohl(networkOrder) - base_;
        if (!IsFakeIP(networkOrder) || offset == 0 || offset > capacity_ || !Lock()) return {};
        std::string domain(entries_[offset - 1].domain, strnlen_s(entries_[offset - 1].domain, 256));
        ReleaseMutex(mutex_); return domain;
    }
    static std::string IpToString(uint32_t networkOrder) {
        in_addr addr{}; addr.s_addr = networkOrder;
        char text[INET_ADDRSTRLEN]{};
        return inet_ntop(AF_INET, &addr, text, sizeof(text)) ? text : "";
    }
};
}
