#pragma once
#include "Paths.hpp"
#include <algorithm>
#include <atomic>
#include <cctype>
#include <mutex>
#include <string>
#include <vector>

namespace Core {
enum class LogLevel : int { Debug, Info, Warn, Error };
// File only: CLI stdout/stderr belong exclusively to the host protocol.
class Logger {
    inline static std::atomic<int> level_{static_cast<int>(LogLevel::Info)};
    inline static std::atomic<bool> enabled_{true};
    inline static std::mutex lock_;
    inline static std::filesystem::path directory_;
    static std::vector<std::filesystem::path> Directories() {
        std::vector<std::filesystem::path> dirs{ModuleDirectory() / L"logs"};
        auto local = Environment(L"LOCALAPPDATA");
        if (!local.empty()) dirs.push_back(std::filesystem::path(local) / L"codex-proxy" / L"logs");
        wchar_t temp[32768]{};
        DWORD count = GetTempPathW(32768, temp);
        if (count && count < 32768) dirs.push_back(std::filesystem::path(temp) / L"codex-proxy-logs");
        return dirs;
    }
    static void Write(LogLevel level, const std::string& message) noexcept {
        if (!IsEnabled(level)) return;
        DWORD savedError = GetLastError();
        try {
            std::lock_guard<std::mutex> guard(lock_);
            SYSTEMTIME now{};
            GetLocalTime(&now);
            wchar_t filename[40]{};
            swprintf_s(filename, L"proxy-%04u%02u%02u.log", now.wYear, now.wMonth, now.wDay);
            auto dirs = Directories();
            if (!directory_.empty()) dirs.insert(dirs.begin(), directory_);
            HANDLE file = INVALID_HANDLE_VALUE;
            for (const auto& dir : dirs) {
                std::error_code ec;
                std::filesystem::create_directories(dir, ec);
                file = CreateFileW((dir / filename).c_str(), FILE_APPEND_DATA,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
                if (file != INVALID_HANDLE_VALUE) { directory_ = dir; break; }
            }
            if (file != INVALID_HANDLE_VALUE) {
                const char* names[]{"DEBUG", "INFO", "WARN", "ERROR"};
                char prefix[100]{};
                sprintf_s(prefix, "%02u:%02u:%02u.%03u [%lu:%lu] [%s] ",
                    now.wHour, now.wMinute, now.wSecond, now.wMilliseconds,
                    GetCurrentProcessId(), GetCurrentThreadId(), names[static_cast<int>(level)]);
                std::string clean = message.substr(0, 16384);
                for (char& c : clean) if (c == '\r' || c == '\n' || c == '\0') c = ' ';
                std::string line = std::string(prefix) + clean + "\r\n";
                static HANDLE mutex = CreateMutexW(nullptr, FALSE, L"Local\\CodexProxy_LogFileMutex");
                DWORD wait = mutex ? WaitForSingleObject(mutex, 1000) : WAIT_FAILED;
                if (wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED) {
                    DWORD written = 0;
                    WriteFile(file, line.data(), static_cast<DWORD>(line.size()), &written, nullptr);
                    ReleaseMutex(mutex);
                }
                CloseHandle(file);
            }
        } catch (...) { /* Never throw through a host API. */ }
        SetLastError(savedError);
    }
public:
    static bool IsEnabled(LogLevel level) { return enabled_ && static_cast<int>(level) >= level_; }
    static void SetEnabled(bool value) { enabled_ = value; }
    static void SetLevel(LogLevel level) { level_ = static_cast<int>(level); }
    static bool SetLevelFromString(std::string value) {
        std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (value == "debug") SetLevel(LogLevel::Debug);
        else if (value == "info") SetLevel(LogLevel::Info);
        else if (value == "warn" || value == "warning") SetLevel(LogLevel::Warn);
        else if (value == "error") SetLevel(LogLevel::Error);
        else return false;
        return true;
    }
    static std::string GetLogDirectoryPath() { std::lock_guard<std::mutex> guard(lock_); return directory_.u8string(); }
    static void Debug(const std::string& s) { Write(LogLevel::Debug, s); }
    static void Info(const std::string& s) { Write(LogLevel::Info, s); }
    static void Warn(const std::string& s) { Write(LogLevel::Warn, s); }
    static void Error(const std::string& s) { Write(LogLevel::Error, s); }
};
}
