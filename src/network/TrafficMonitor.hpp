// Derived from antigravity-proxy (BSD-2-Clause); see LICENSE.txt / AUTHORS.txt.
#pragma once
#include <winsock2.h>
#include <string>
#include "../core/Logger.hpp"
#include "../core/Config.hpp"

namespace Network {
    
    // 流量监控器
    // 用于记录 send/recv 流量摘要
    class TrafficMonitor {
    public:
        static TrafficMonitor& Instance() {
            static TrafficMonitor instance;
            return instance;
        }
        
        // 记录发送数据
        void LogSend(SOCKET s, const char* buf, int len) {
            if (!Core::Config::Instance().trafficLogging) return;
            
            std::string summary = FormatTrafficSummary("SEND", s, buf, len);
            Core::Logger::Info(summary);
        }
        
        // 记录接收数据
        void LogRecv(SOCKET s, const char* buf, int len) {
            if (!Core::Config::Instance().trafficLogging) return;
            
            std::string summary = FormatTrafficSummary("RECV", s, buf, len);
            Core::Logger::Info(summary);
        }
        
    private:
        // 格式化流量摘要
        std::string FormatTrafficSummary(const char* direction, SOCKET s, const char*, int len) {
            std::string result = "[" + std::string(direction) + "] Socket=" + std::to_string((uintptr_t)s);
            result += " Len=" + std::to_string(len);
            
            return result;
        }
    };
}
