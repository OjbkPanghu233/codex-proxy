#include <windows.h>
extern "C" __declspec(dllimport) void CodexProxy_Bootstrap() noexcept;
BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) CodexProxy_Bootstrap();
    return TRUE;
}
