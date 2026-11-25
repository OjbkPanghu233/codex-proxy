#pragma once
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <cassert>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>
#include "core/Config.hpp"
struct Winsock {
    Winsock() { WSADATA data{}; assert(WSAStartup(MAKEWORD(2,2), &data) == 0); }
    ~Winsock() { WSACleanup(); }
};
struct TestDirectory {
    std::filesystem::path path;
    TestDirectory() {
        wchar_t temp[32768]{}; GetTempPathW(32768, temp);
        path = std::filesystem::path(temp) / (L"codex-proxy-test-" + std::to_wstring(GetCurrentProcessId()));
        std::filesystem::create_directories(path);
    }
    ~TestDirectory() { std::error_code ec; std::filesystem::remove_all(path, ec); }
};
inline void JsonFile(const std::filesystem::path& path, const nlohmann::json& json) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream file(path); file << json.dump(2); assert(file.good());
}
struct Socket {
    SOCKET value = INVALID_SOCKET;
    explicit Socket(SOCKET s = INVALID_SOCKET) : value(s) {}
    ~Socket() { if (value != INVALID_SOCKET) closesocket(value); }
    Socket(const Socket&) = delete;
    operator SOCKET() const { return value; }
};
inline SOCKET Listen(uint16_t* port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); assert(s != INVALID_SOCKET);
    sockaddr_in address{}; address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(s, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
    assert(listen(s, 8) == 0);
    int size = sizeof(address); assert(getsockname(s, reinterpret_cast<sockaddr*>(&address), &size) == 0);
    *port = ntohs(address.sin_port); return s;
}
inline SOCKET LoopbackConnect(uint16_t port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); assert(s != INVALID_SOCKET);
    sockaddr_in address{}; address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK); address.sin_port = htons(port);
    assert(connect(s, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0); return s;
}
