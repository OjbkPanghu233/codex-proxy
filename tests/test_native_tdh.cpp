#ifdef NDEBUG
#undef NDEBUG
#endif
#include <windows.h>
#include <evntcons.h>
#include <tdh.h>
#include <cassert>
int main() {
    // These references must be in the PE import table, just like native Codex.
    ULONG size=0; EVENT_RECORD event{};
    auto result=TdhGetEventInformation(&event,0,nullptr,nullptr,&size);
    assert(result != ERROR_PROC_NOT_FOUND);
    auto core=GetModuleHandleW(L"codex_proxy.dll"); assert(core);
    auto wait=reinterpret_cast<DWORD(*)(DWORD)>(GetProcAddress(core,"CodexProxy_WaitReady"));
    assert(wait && wait(10000)==1);
}
