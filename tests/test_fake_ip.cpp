#include "Test.hpp"
#include "network/FakeIP.hpp"
int wmain(int argc,wchar_t** argv) {
    Winsock wsa;
    auto& config = Core::Config::Instance();
    config.fakeIp.cidr = "198.18.0.0/30";
    config.loadedPath = argc==3 ? argv[2] : L"fake-ip-test-" + std::to_wstring(GetCurrentProcessId());
    auto& pool = Network::FakeIP::Instance();
    if(argc==3) { assert(pool.Alloc("shared-child.example")); return 37; }
    auto first = pool.Alloc("A.Example.");
    assert(first && pool.Alloc("a.example") == first);
    assert(pool.GetDomain(first) == "a.example");
    auto second = pool.Alloc("b.example"); assert(second != first);
    auto third = pool.Alloc("c.example"); assert(third == first);
    assert(pool.GetDomain(first) == "c.example");
    assert(pool.Alloc("a.example") == second); // stale cache must be validated
    assert(!pool.Alloc(std::string(256,'a')) && !pool.Alloc(""));
    assert(pool.IsFakeIP(first) && !pool.IsFakeIP(htonl(INADDR_LOOPBACK)));
    wchar_t executable[32768]{}; GetModuleFileNameW(nullptr,executable,32768);
    auto command=L"\""+std::wstring(executable)+L"\" --child \""+config.loadedPath.wstring()+L"\"";
    STARTUPINFOW si{}; si.cb=sizeof(si); PROCESS_INFORMATION pi{};
    assert(CreateProcessW(executable,command.data(),nullptr,nullptr,FALSE,0,nullptr,nullptr,&si,&pi));
    assert(WaitForSingleObject(pi.hProcess,10000)==WAIT_OBJECT_0);
    DWORD exit=0; assert(GetExitCodeProcess(pi.hProcess,&exit) && exit==37);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    assert(pool.GetDomain(first)=="shared-child.example");
}
