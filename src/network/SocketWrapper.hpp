// Derived from antigravity-proxy (BSD-2-Clause); see LICENSE.txt / AUTHORS.txt.
#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <memory>
#include "../core/Logger.hpp"

namespace Network {
    class SocketWrapper {
        SOCKET m_sock;
        int oldRecv_ = 0, oldSend_ = 0;
        bool restore_ = false;
    public:
        SocketWrapper(SOCKET sock) : m_sock(sock) {}
        ~SocketWrapper() {
            if (restore_) {
                int error = WSAGetLastError();
                setsockopt(m_sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&oldRecv_), sizeof(oldRecv_));
                setsockopt(m_sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&oldSend_), sizeof(oldSend_));
                WSASetLastError(error);
            }
        }
        SocketWrapper(const SocketWrapper&) = delete;
        SocketWrapper& operator=(const SocketWrapper&) = delete;

        void SetTimeouts(int recv_ms, int send_ms) {
            if (m_sock == INVALID_SOCKET) return;
            if (!restore_) {
                int size = sizeof(int);
                if (getsockopt(m_sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&oldRecv_), &size) != 0) return;
                size = sizeof(int);
                if (getsockopt(m_sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<char*>(&oldSend_), &size) != 0) return;
                restore_ = true;
            }
            setsockopt(m_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&recv_ms, sizeof(recv_ms));
            setsockopt(m_sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&send_ms, sizeof(send_ms));
        }

        static bool RedirectToProxy(sockaddr_in* addr, const std::string& proxyHost, int proxyPort) {
            if (!addr) return false;
            // 优先直接解析 IPv4 字符串，失败时尝试 DNS 解析
            if (inet_pton(AF_INET, proxyHost.c_str(), &addr->sin_addr) != 1) {
                addrinfo hints{};
                hints.ai_family = AF_INET;
                hints.ai_socktype = SOCK_STREAM;
                hints.ai_protocol = IPPROTO_TCP;
                addrinfo* res = nullptr;
                int rc = getaddrinfo(proxyHost.c_str(), nullptr, &hints, &res);
                if (rc != 0 || !res) return false;
                auto* resolved = (sockaddr_in*)res->ai_addr;
                addr->sin_addr = resolved->sin_addr;
                freeaddrinfo(res);
            }
            addr->sin_port = htons(static_cast<u_short>(proxyPort));
            return true;
        }
    };
}
