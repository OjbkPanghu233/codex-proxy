#ifdef NDEBUG
#undef NDEBUG
#endif
#include <windows.h>
#include <evntcons.h>
#include <tdh.h>
#include <cassert>
#include <string>
int wmain(int argc, wchar_t** argv) {
    assert(argc==3);
    HMODULE shim=LoadLibraryW(argv[1]); assert(shim);
    HMODULE core=GetModuleHandleW(L"codex_proxy.dll"); assert(core);
    auto wait=reinterpret_cast<DWORD(*)(DWORD)>(GetProcAddress(core,"CodexProxy_WaitReady"));
    assert(wait && wait(10000)==2); // non-target/no config: loading shim is inert
    wchar_t system[32768]{}; GetSystemDirectoryW(system,32768);
    HMODULE native=LoadLibraryW((std::wstring(system)+L"\\tdh.dll").c_str()); assert(native);
    auto shimEnum=reinterpret_cast<decltype(&TdhEnumerateProviders)>(GetProcAddress(shim,"TdhEnumerateProviders"));
    auto nativeEnum=reinterpret_cast<decltype(&TdhEnumerateProviders)>(GetProcAddress(native,"TdhEnumerateProviders"));
    ULONG a=0,b=0;
    assert(shimEnum && nativeEnum && shimEnum(nullptr,&a)==nativeEnum(nullptr,&b)); assert(a==b && a>0);
    auto eventA=reinterpret_cast<decltype(&TdhGetEventInformation)>(GetProcAddress(shim,"TdhGetEventInformation"));
    auto eventB=reinterpret_cast<decltype(&TdhGetEventInformation)>(GetProcAddress(native,"TdhGetEventInformation"));
    EVENT_RECORD event{}; a=b=0;
    assert(eventA(&event,0,nullptr,nullptr,&a)==eventB(&event,0,nullptr,nullptr,&b)); assert(a==b);
    for (auto name : {"TdhGetProperty","TdhGetPropertySize","TdhFormatProperty","TdhLoadManifest","TdhUnloadManifest","TdhEnumerateManifestProviderEvents","TdhGetManifestEventInformation"}) assert(GetProcAddress(shim,name));
    HMODULE version=LoadLibraryW(argv[2]); assert(version);
    auto getSize=reinterpret_cast<DWORD(WINAPI*)(LPCWSTR,LPDWORD)>(GetProcAddress(version,"GetFileVersionInfoSizeW"));
    assert(getSize && getSize((std::wstring(system)+L"\\kernel32.dll").c_str(),nullptr)>0);
    FreeLibrary(version); FreeLibrary(shim); FreeLibrary(native);
}
