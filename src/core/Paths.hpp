#pragma once
#include <windows.h>
#include <filesystem>
#include <string>
namespace Core {
inline std::wstring Environment(const wchar_t* name) {
    DWORD count = GetEnvironmentVariableW(name, nullptr, 0);
    if (!count) return {};
    std::wstring value(count, L'\0');
    DWORD size = GetEnvironmentVariableW(name, value.data(), count);
    if (!size || size >= count) return {};
    value.resize(size);
    return value;
}
inline std::filesystem::path ModulePath() {
    HMODULE module = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCWSTR>(&ModulePath), &module)) return {};
    std::wstring path(32768, L'\0');
    DWORD size = GetModuleFileNameW(module, path.data(), static_cast<DWORD>(path.size()));
    if (!size || size == path.size()) return {};
    path.resize(size);
    return path;
}
inline std::filesystem::path ModuleDirectory() { return ModulePath().parent_path(); }
inline std::wstring ReadyEventName(DWORD pid) {
    return L"Local\\CodexProxy_Ready_" + std::to_wstring(pid);
}
}
