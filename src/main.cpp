#include <winsock2.h>
#include <windows.h>
#include <atomic>
#include "core/Config.hpp"
#include "core/DllIdentity.hpp"
#include "core/LaunchRequest.hpp"
#include "hooks/Hooks.hpp"
#include "hooks/ProcessName.hpp"

namespace {
std::atomic<DWORD> status{0}; // 0=starting, 1=active, 2=bypass, 3=failure
HANDLE ready = nullptr;
HANDLE owner = nullptr;
DWORD WINAPI Initialize(void*) noexcept {
    try {
        auto& config = Core::Config::Instance();
        Core::LaunchRequest request{};
        bool requested=Core::ReadLaunchRequest(request);
        if (!config.Load(requested ? std::filesystem::path(request.config) : std::filesystem::path())) { status = 2; SetEvent(ready); return 0; }
        wchar_t executable[32768]{};
        GetModuleFileNameW(nullptr, executable, 32768);
        auto path = std::filesystem::path(executable);
        int count = WideCharToMultiByte(CP_UTF8, 0, GetCommandLineW(), -1, nullptr, 0, nullptr, nullptr);
        std::string command(count > 0 ? count : 1, '\0');
        if (count > 0) WideCharToMultiByte(CP_UTF8, 0, GetCommandLineW(), -1, command.data(), count, nullptr, nullptr);
        auto name = path.filename().u8string();
        std::error_code imageError;
        bool desktopImage=std::filesystem::is_regular_file(path.parent_path()/L"resources/app.asar",imageError);
        auto role = Hooks::ClassifyProcess(name, command, desktopImage);
        bool forced=requested && request.forceTarget && Core::SameImage(path,request.image);
        if ((!config.ShouldInject(name) && !forced) || !Hooks::IsInjectableRole(role)) {
            status = 2; SetEvent(ready); return 0;
        }
        const auto mutexName = L"Local\\CodexProxy_Hooks_" + std::to_wstring(GetCurrentProcessId());
        owner = CreateMutexW(nullptr, FALSE, mutexName.c_str());
        DWORD error = GetLastError();
        if (!owner) { status = 3; SetEvent(ready); return 0; }
        if (error == ERROR_ALREADY_EXISTS) {
            CloseHandle(owner); owner = nullptr;
            status = 2; // The first copy will signal the shared event after installation.
            return 0;
        }
        bool network = Hooks::EnableNetworkHooks(role,config.desktopHostNetworkHooks) || role == Hooks::ProcessRole::NotTarget;
        Core::Logger::Info("Codex-Proxy " + Core::GetDllIdentity() +
            (network ? " scope=network+process" : " scope=process-only"));
        if (Hooks::Install(network)) status = 1;
        else { CloseHandle(owner); owner = nullptr; status = 3; }
    } catch (...) {
        if (owner) { CloseHandle(owner); owner = nullptr; }
        status = 3;
    }
    SetEvent(ready);
    return 0;
}
}
// Static PE imports from tdh/version force safe loader ordering. No work here.
extern "C" __declspec(dllexport) void CodexProxy_Bootstrap() noexcept {}
extern "C" __declspec(dllexport) DWORD CodexProxy_WaitReady(DWORD timeout) noexcept {
    if (!ready || WaitForSingleObject(ready, timeout) != WAIT_OBJECT_0) return 0;
    return status.load();
}
BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        // Hooks, worker code and outstanding I/O must remain valid until process exit.
        HMODULE pinned = nullptr;
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
            reinterpret_cast<LPCWSTR>(&CodexProxy_Bootstrap), &pinned);
        ready = CreateEventW(nullptr, TRUE, FALSE, Core::ReadyEventName(GetCurrentProcessId()).c_str());
        if (!ready) return FALSE;
        HANDLE thread = CreateThread(nullptr, 0, Initialize, nullptr, 0, nullptr);
        if (!thread) { CloseHandle(ready); ready = nullptr; return FALSE; }
        CloseHandle(thread);
    }
    // No waits, LoadLibrary, MinHook or complex teardown while holding loader lock.
    return TRUE;
}
