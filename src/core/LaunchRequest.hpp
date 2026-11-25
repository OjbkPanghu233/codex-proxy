#pragma once
#include "Paths.hpp"
#include <algorithm>
namespace Core {
// A short-lived, PID-scoped bootstrap request also works with an existing process
// whose environment cannot inherit the launcher's CODEX_PROXY_CONFIG.
struct LaunchRequest {
    DWORD magic = 0x43504c32;
    DWORD pid = 0;
    DWORD forceTarget = 0;
    wchar_t config[32768]{};
    wchar_t image[32768]{};
};
inline std::wstring LaunchRequestName(DWORD pid) { return L"Local\\CodexProxy_Launch_" + std::to_wstring(pid); }
// The owner must keep this handle until DLL initialization has signalled Ready.
inline HANDLE CreateLaunchRequest(DWORD pid, const std::filesystem::path& config,
    const std::filesystem::path& image = {}, bool force = false) {
    if (!pid || config.empty() || config.native().size() >= 32768 || image.native().size() >= 32768) return nullptr;
    HANDLE mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE,
        0, sizeof(LaunchRequest), LaunchRequestName(pid).c_str());
    DWORD error = GetLastError();
    if (!mapping) return nullptr;
    if (error == ERROR_ALREADY_EXISTS) { CloseHandle(mapping); return nullptr; }
    auto request = static_cast<LaunchRequest*>(MapViewOfFile(mapping, FILE_MAP_WRITE, 0, 0, sizeof(LaunchRequest)));
    if (!request) { CloseHandle(mapping); return nullptr; }
    *request = LaunchRequest{}; request->pid = pid; request->forceTarget = force;
    wcscpy_s(request->config, config.c_str()); wcscpy_s(request->image, image.c_str());
    UnmapViewOfFile(request);
    return mapping;
}
inline bool ReadLaunchRequest(LaunchRequest& value) {
    HANDLE mapping=OpenFileMappingW(FILE_MAP_READ,FALSE,LaunchRequestName(GetCurrentProcessId()).c_str());
    if(!mapping) return false;
    auto data=static_cast<const LaunchRequest*>(MapViewOfFile(mapping,FILE_MAP_READ,0,0,sizeof(LaunchRequest)));
    if(data) { value=*data; UnmapViewOfFile(data); }
    CloseHandle(mapping);
    return data && value.magic==0x43504c32 && value.pid==GetCurrentProcessId() &&
        value.config[32767]==0 && value.image[32767]==0;
}
inline bool SameImage(const std::filesystem::path& left,const std::filesystem::path& right) {
    std::error_code ec;
    auto a=std::filesystem::weakly_canonical(left,ec).wstring();
    if(ec) return false;
    auto b=std::filesystem::weakly_canonical(right,ec).wstring();
    return !ec && _wcsicmp(a.c_str(),b.c_str())==0;
}
}
