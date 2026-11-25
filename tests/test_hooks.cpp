#include "Test.hpp"
#include <mswsock.h>
#include <winhttp.h>
#include <atomic>
#include <iostream>
#include "network/FakeIP.hpp"
#include "network/LocalTargetPolicy.hpp"
#include "core/LaunchRequest.hpp"

static HANDLE dnsDone=nullptr;
static HANDLE datagramSent=nullptr;
static std::atomic<int> udpCallbacks{0};
static std::atomic<DWORD> udpCallbackBytes{0};
static void CALLBACK UdpCallback(DWORD error,DWORD bytes,LPWSAOVERLAPPED,DWORD) {
    assert(error==0); udpCallbackBytes=bytes; ++udpCallbacks;
}
static std::atomic<DWORD> dnsError{~0u};
static std::atomic<int> callbacks{0};
static void CALLBACK DnsCallback(DWORD error, DWORD, LPOVERLAPPED ovl) {
    assert(ovl); dnsError=error; ++callbacks; SetEvent(dnsDone);
}
static void FakeAddress(const sockaddr* address) {
    assert(address);
    if (address->sa_family==AF_INET) assert((ntohl(reinterpret_cast<const sockaddr_in*>(address)->sin_addr.s_addr)&0xfffe0000u)==0xc6120000u);
    else {
        auto& v6=reinterpret_cast<const sockaddr_in6*>(address)->sin6_addr;
        assert(IN6_IS_ADDR_V4MAPPED(&v6));
        in_addr v4{}; memcpy(&v4,v6.u.Byte+12,4); assert((ntohl(v4.s_addr)&0xfffe0000u)==0xc6120000u);
    }
}
static void DnsTests() {
    addrinfo hints{}; hints.ai_socktype=SOCK_STREAM;
    addrinfo* result=nullptr;
    assert(getaddrinfo("phase1.invalid","443",&hints,&result)==0); FakeAddress(result->ai_addr); freeaddrinfo(result);
    hints.ai_flags=AI_NUMERICHOST;
    assert(getaddrinfo("phase1.invalid","443",&hints,&result)!=0);
    ADDRINFOW wh{}; wh.ai_family=AF_INET6; wh.ai_socktype=SOCK_STREAM;
    PADDRINFOW wr=nullptr;
    assert(GetAddrInfoW(L"phase1.invalid",L"443",&wh,&wr)==0); FakeAddress(wr->ai_addr); FreeAddrInfoW(wr);
    auto host=gethostbyname("phase1.invalid"); assert(host && host->h_addrtype==AF_INET);
    assert((ntohl(*reinterpret_cast<uint32_t*>(host->h_addr_list[0]))&0xfffe0000u)==0xc6120000u);
    for (auto family : {AF_INET,AF_INET6}) {
        ADDRINFOEXW ex{}; ex.ai_family=family; ex.ai_socktype=SOCK_STREAM;
        PADDRINFOEXW er=nullptr;
        assert(GetAddrInfoExW(L"phase1.invalid",L"443",NS_DNS,nullptr,&ex,&er,nullptr,nullptr,nullptr,nullptr)==0);
        FakeAddress(er->ai_addr); FreeAddrInfoExW(er); er=nullptr;
        OVERLAPPED ovl{}; ovl.hEvent=CreateEventW(nullptr,TRUE,FALSE,nullptr); assert(ovl.hEvent);
        HANDLE cancel=nullptr;
        int rc=GetAddrInfoExW(L"phase1.invalid",L"443",NS_DNS,nullptr,&ex,&er,nullptr,&ovl,nullptr,&cancel);
        assert(rc==0 || rc==WSA_IO_PENDING);
        if (rc==WSA_IO_PENDING) { assert(WaitForSingleObject(ovl.hEvent,10000)==WAIT_OBJECT_0); assert(GetAddrInfoExOverlappedResult(&ovl)==0); }
        assert(er); FakeAddress(er->ai_addr); FreeAddrInfoExW(er); CloseHandle(ovl.hEvent);
    }
    ADDRINFOEXW ex{}; ex.ai_family=AF_INET; ex.ai_socktype=SOCK_STREAM;
    PADDRINFOEXW er=nullptr; OVERLAPPED ovl{}; HANDLE cancel=nullptr;
    dnsDone=CreateEventW(nullptr,TRUE,FALSE,nullptr); assert(dnsDone);
    int rc=GetAddrInfoExW(L"phase1.invalid",L"443",NS_ALL,nullptr,&ex,&er,nullptr,&ovl,DnsCallback,&cancel);
    assert(rc==0 || rc==WSA_IO_PENDING);
    if (rc==WSA_IO_PENDING) { assert(WaitForSingleObject(dnsDone,10000)==WAIT_OBJECT_0); assert(dnsError==0 && callbacks==1); }
    assert(er); FakeAddress(er->ai_addr); FreeAddrInfoExW(er); CloseHandle(dnsDone);
    result=nullptr; hints.ai_flags=0;
    assert(getaddrinfo("localhost","1455",&hints,&result)==0);
    for(auto p=result;p;p=p->ai_next) assert(Network::IsLoopbackSockaddr(p->ai_addr,static_cast<int>(p->ai_addrlen)));
    freeaddrinfo(result);
}
static DWORD Child(const std::filesystem::path& executable, const std::wstring& args, DWORD flags=0, bool ansi=false) {
    std::wstring command=L"\""+executable.wstring()+L"\" "+args;
    STARTUPINFOW si{}; si.cb=sizeof(si); PROCESS_INFORMATION pi{};
    if(ansi) {
        int count=WideCharToMultiByte(CP_ACP,0,command.c_str(),-1,nullptr,0,nullptr,nullptr); assert(count>0);
        std::string narrow(count,'\0'); assert(WideCharToMultiByte(CP_ACP,0,command.c_str(),-1,narrow.data(),count,nullptr,nullptr));
        auto image=executable.string(); STARTUPINFOA startup{}; startup.cb=sizeof(startup);
        assert(CreateProcessA(image.c_str(),narrow.data(),nullptr,nullptr,FALSE,flags,nullptr,nullptr,&startup,&pi));
    } else assert(CreateProcessW(executable.c_str(),command.data(),nullptr,nullptr,FALSE,flags,nullptr,nullptr,&si,&pi));
    if(flags&CREATE_SUSPENDED) { DWORD code=0; assert(GetExitCodeProcess(pi.hProcess,&code) && code==STILL_ACTIVE); assert(ResumeThread(pi.hThread)==1); }
    assert(WaitForSingleObject(pi.hProcess,15000)==WAIT_OBJECT_0);
    DWORD code=0; assert(GetExitCodeProcess(pi.hProcess,&code)); CloseHandle(pi.hProcess); CloseHandle(pi.hThread); return code;
}
static std::vector<uint8_t> Read(SOCKET s, size_t size) {
    std::vector<uint8_t> bytes(size); size_t position=0;
    while(position<size) { int n=recv(s,reinterpret_cast<char*>(bytes.data()+position),static_cast<int>(size-position),0); assert(n>0); position+=n; }
    return bytes;
}
static void SocksServer(SOCKET listener, bool udp, uint16_t relayPort=0, bool reject=false) {
    Socket peer(accept(listener,nullptr,nullptr)); assert(peer.value!=INVALID_SOCKET);
    auto greeting=Read(peer,2); assert(greeting[0]==5); Read(peer,greeting[1]);
    assert(send(peer,"\5\0",2,0)==2);
    auto request=Read(peer,4); assert(request[1]==(udp?3:1));
    if(request[3]==3) { auto length=Read(peer,1)[0]; auto host=Read(peer,length); assert(!host.empty()); }
    else Read(peer,request[3]==1?4:16);
    Read(peer,2);
    uint8_t response[]{5,static_cast<uint8_t>(reject?5:0),0,1,127,0,0,1,static_cast<uint8_t>(relayPort>>8),static_cast<uint8_t>(relayPort)};
    assert(send(peer,reinterpret_cast<char*>(response),sizeof(response),0)==sizeof(response));
    if(reject) return;
    if(udp) { char byte; recv(peer,&byte,1,0); }
    else { auto payload=Read(peer,4); assert(payload==std::vector<uint8_t>({'P','I','N','G'})); assert(send(peer,"PONG",4,0)==4); }
}
int wmain(int argc,wchar_t** argv) {
    if(argc>=4 && std::wstring(argv[1])==L"--config-tree-child") {
        auto core=GetModuleHandleW(L"codex_proxy.dll"); assert(core);
        auto wait=reinterpret_cast<DWORD(*)(DWORD)>(GetProcAddress(core,"CodexProxy_WaitReady")); assert(wait && wait(10000)==1);
        Winsock wsa; addrinfo hints{}; hints.ai_family=AF_INET; hints.ai_socktype=SOCK_STREAM; addrinfo* result=nullptr;
        assert(getaddrinfo("tree-config.invalid","443",&hints,&result)==0); FakeAddress(result->ai_addr);
        auto address=reinterpret_cast<sockaddr_in*>(result->ai_addr)->sin_addr.s_addr; freeaddrinfo(result);
        // The shared allocator can assign a fresh slot in another process.
        // Both generations must use the custom /29, while the hostile inherited
        // configuration would disable FakeIP altogether.
        auto expected=std::stoul(argv[3]); assert((ntohl(address)&0xfffffff8u)==(ntohl(expected)&0xfffffff8u));
        if(std::wstring(argv[2])==L"1") {
            wchar_t executable[32768]{}; GetModuleFileNameW(nullptr,executable,32768);
            auto args=L"--config-tree-child 2 "+std::to_wstring(address);
            assert(Child(executable,args,0,false)==37);
            assert(Child(executable,args,CREATE_SUSPENDED,true)==37);
        }
        return 37;
    }
    if(argc>=2 && std::wstring(argv[1])==L"--injected-child") {
        auto core=GetModuleHandleW(L"codex_proxy.dll"); if(!core) return 20;
        auto wait=reinterpret_cast<DWORD(*)(DWORD)>(GetProcAddress(core,"CodexProxy_WaitReady")); return wait && wait(10000)==1?37:21;
    }
    if(argc>=2 && std::wstring(argv[1])==L"--plain-child") return GetModuleHandleW(L"codex_proxy.dll")?22:38;
    assert(argc>=3); std::wstring scenario=argv[2]; Winsock wsa; TestDirectory tmp;
    std::filesystem::path dll=std::filesystem::absolute(argv[1]);
    uint16_t proxyPort=7890,relayPort=0;
    Socket listener,relay;
    std::thread server,udpServer;
    bool isUdp=scenario==L"udp" || scenario==L"udp_callback" || scenario==L"udp_immediate_callback" || scenario==L"udp_event";
    bool isIocp=scenario==L"iocp" || scenario==L"iocp_fail" || scenario==L"iocp_fail_ex";
    bool transport=scenario==L"tcp" || isIocp || isUdp;
    if(transport) listener.value=Listen(&proxyPort);
    if(isUdp) {
        relay.value=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP); assert(relay.value!=INVALID_SOCKET);
        sockaddr_in addr{}; addr.sin_family=AF_INET; addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        assert(bind(relay,reinterpret_cast<sockaddr*>(&addr),sizeof(addr))==0);
        int size=sizeof(addr); assert(getsockname(relay,reinterpret_cast<sockaddr*>(&addr),&size)==0); relayPort=ntohs(addr.sin_port);
        datagramSent=CreateEventW(nullptr,TRUE,FALSE,nullptr); assert(datagramSent);
        udpServer=std::thread([&] {
            uint8_t packet[1024]{}; sockaddr_storage source{}; int len=sizeof(source);
            int count=recvfrom(relay,reinterpret_cast<char*>(packet),sizeof(packet),0,reinterpret_cast<sockaddr*>(&source),&len); assert(count>10);
            assert(sendto(relay,reinterpret_cast<char*>(packet),count,0,reinterpret_cast<sockaddr*>(&source),len)==count);
            SetEvent(datagramSent);
        });
    }
    if(transport) server=std::thread([&]{ SocksServer(listener,isUdp,relayPort,scenario==L"iocp_fail" || scenario==L"iocp_fail_ex"); });
    nlohmann::json config={
        {"proxy",{{"host","127.0.0.1"},{"port",scenario==L"disabled"?0:proxyPort},{"ignore_system_proxy",scenario!=L"winhttp_off"}}},
        {"target_processes",{"test_hooks.exe","chatgpt.exe"}},
        {"rules",{{"allowed_ports",nlohmann::json::array()},{"udp_mode","proxy"}}},
        {"desktop_host_network_hooks",scenario!=L"scope_main"},
        {"logging",{{"level","debug"}}}
    };
    auto configPath=tmp.path/L"config.json"; JsonFile(configPath,config);
    HANDLE request=nullptr;
    if(scenario==L"child_config_request") {
        config["fake_ip"]={{"cidr","198.18.0.0/29"}}; JsonFile(configPath,config);
        SetEnvironmentVariableW(L"CODEX_PROXY_CONFIG",nullptr);
        request=Core::CreateLaunchRequest(GetCurrentProcessId(),configPath); assert(request);
    } else SetEnvironmentVariableW(L"CODEX_PROXY_CONFIG",configPath.c_str());
    if((scenario==L"scope_main" || scenario==L"scope_main_on" || scenario==L"scope_renderer") && argc==3) {
        auto host=tmp.path/L"ChatGPT.exe";
        wchar_t executable[32768]{}; GetModuleFileNameW(nullptr,executable,32768);
        std::filesystem::copy_file(executable,host);
        auto args=L"\""+dll.wstring()+L"\" "+scenario+L" --scope";
        if(scenario==L"scope_renderer") args+=L" --type=renderer";
        assert(Child(host,args)==0); return 0;
    }
    std::vector<uint8_t> before(16); memcpy(before.data(),reinterpret_cast<void*>(&WinHttpGetIEProxyConfigForCurrentUser),16);
    HMODULE core=LoadLibraryW(dll.c_str()); assert(core);
    auto wait=reinterpret_cast<DWORD(*)(DWORD)>(GetProcAddress(core,"CodexProxy_WaitReady")); assert(wait);
    DWORD status=wait(10000);
    if(request) { CloseHandle(request); request=nullptr; }
    if(scenario==L"scope_renderer") { assert(status==2); return 0; }
    assert(status==1);

    if(scenario==L"child_config_request") {
        // An attach request, not the environment, selected the active config.
        // A conflicting inherited environment must not win in children either.
        auto hostile=tmp.path/L"wrong-child-config.json"; JsonFile(hostile,{{"proxy",{{"port",0}}},{"target_processes",{"test_hooks.exe"}}});
        SetEnvironmentVariableW(L"CODEX_PROXY_CONFIG",hostile.c_str());
        addrinfo hints{}; hints.ai_family=AF_INET; hints.ai_socktype=SOCK_STREAM; addrinfo* result=nullptr;
        assert(getaddrinfo("first-tree-slot.invalid","443",&hints,&result)==0); freeaddrinfo(result);
        assert(getaddrinfo("tree-config.invalid","443",&hints,&result)==0); FakeAddress(result->ai_addr);
        auto address=reinterpret_cast<sockaddr_in*>(result->ai_addr)->sin_addr.s_addr; freeaddrinfo(result);
        wchar_t executable[32768]{}; GetModuleFileNameW(nullptr,executable,32768);
        auto args=L"--config-tree-child 1 "+std::to_wstring(address);
        assert(Child(executable,args,0,false)==37);
        assert(Child(executable,args,CREATE_SUSPENDED,true)==37);
    }

    if(scenario==L"duplicate") {
        auto second=tmp.path/L"second.dll";
        std::filesystem::copy_file(dll,second);
        uint8_t installed[16]{}; memcpy(installed,reinterpret_cast<void*>(&connect),16);
        HMODULE copy=LoadLibraryW(second.c_str()); assert(copy);
        auto waitCopy=reinterpret_cast<DWORD(*)(DWORD)>(GetProcAddress(copy,"CodexProxy_WaitReady")); assert(waitCopy);
        DWORD secondStatus=0;
        for(int i=0;i<100 && !secondStatus;++i) { secondStatus=waitCopy(10); if(!secondStatus) Sleep(1); }
        assert(secondStatus==2 && !memcmp(installed,reinterpret_cast<void*>(&connect),16));
    }
    if(scenario==L"dns" || scenario==L"scope_main_on") DnsTests();
    if(scenario==L"winhttp") {
        WINHTTP_CURRENT_USER_IE_PROXY_CONFIG ie{}; memset(&ie,0xcc,sizeof(ie));
        assert(WinHttpGetIEProxyConfigForCurrentUser(&ie));
        assert(!ie.fAutoDetect && !ie.lpszProxy && !ie.lpszProxyBypass && !ie.lpszAutoConfigUrl);
        WINHTTP_PROXY_INFO info{};
        assert(!WinHttpGetProxyForUrl(nullptr,L"https://example.invalid",nullptr,&info));
        assert(GetLastError()==ERROR_WINHTTP_AUTODETECTION_FAILED);
    }
    if(scenario==L"winhttp_off" || scenario==L"disabled" || scenario==L"scope_main") {
        assert(!memcmp(before.data(),reinterpret_cast<void*>(&WinHttpGetIEProxyConfigForCurrentUser),16));
        if(scenario!=L"winhttp_off") {
            addrinfo hints{}; hints.ai_flags=AI_NUMERICHOST; addrinfo* addresses=nullptr;
            assert(getaddrinfo("unchanged.invalid",nullptr,&hints,&addresses)!=0);
        }
    }
    if(scenario==L"local") {
        uint16_t port=0; Socket localListener(Listen(&port));
        Socket client(LoopbackConnect(port)); Socket peer(accept(localListener,nullptr,nullptr));
        assert(send(client,"IPC",3,0)==3); assert(Read(peer,3)==std::vector<uint8_t>({'I','P','C'}));
        assert(shutdown(client,SD_SEND)==0);
        Socket byName(socket(AF_INET,SOCK_STREAM,IPPROTO_TCP));
        sockaddr_storage local{},remote{}; DWORD ll=sizeof(local),rl=sizeof(remote); auto service=std::to_string(port);
        assert(WSAConnectByNameA(byName,"localhost",service.c_str(),&ll,reinterpret_cast<sockaddr*>(&local),&rl,reinterpret_cast<sockaddr*>(&remote),nullptr,nullptr));
        assert(ll && rl && Network::IsLocalSockaddr(reinterpret_cast<sockaddr*>(&remote),rl));
    }
    if(scenario==L"injection") {
        wchar_t executable[32768]{}; GetModuleFileNameW(nullptr,executable,32768);
        assert(Child(executable,L"--injected-child")==37);
        assert(Child(executable,L"--injected-child",CREATE_SUSPENDED)==37);
        for(auto name : {L"powershell.exe",L"git.exe",L"node.exe"}) {
            auto tool=tmp.path/name; std::filesystem::copy_file(executable,tool);
            assert(Child(tool,L"--plain-child")==38);
        }
        auto renderer=tmp.path/L"ChatGPT.exe"; std::filesystem::copy_file(executable,renderer);
        assert(Child(renderer,L"--plain-child --type=renderer")==38);
    }
    if(transport) {
        addrinfo hints{}; hints.ai_family=AF_INET; hints.ai_socktype=isUdp?SOCK_DGRAM:SOCK_STREAM;
        addrinfo* target=nullptr; assert(getaddrinfo("proxy-test.invalid","443",&hints,&target)==0); FakeAddress(target->ai_addr);
        Socket client(WSASocketW(AF_INET,hints.ai_socktype,0,nullptr,0,WSA_FLAG_OVERLAPPED)); assert(client.value!=INVALID_SOCKET);
        HANDLE iocp=nullptr;
        if(scenario==L"tcp") {
            assert(connect(client,target->ai_addr,static_cast<int>(target->ai_addrlen))==0);
            assert(send(client,"PING",4,0)==4); assert(Read(client,4)==std::vector<uint8_t>({'P','O','N','G'}));
        } else if(isIocp) {
            sockaddr_in bound{}; bound.sin_family=AF_INET; assert(bind(client,reinterpret_cast<sockaddr*>(&bound),sizeof(bound))==0);
            iocp=CreateIoCompletionPort(reinterpret_cast<HANDLE>(client.value),nullptr,7,1); assert(iocp);
            GUID guid=WSAID_CONNECTEX; LPFN_CONNECTEX connectEx=nullptr; DWORD bytes=0;
            assert(WSAIoctl(client,SIO_GET_EXTENSION_FUNCTION_POINTER,&guid,sizeof(guid),&connectEx,sizeof(connectEx),&bytes,nullptr,nullptr)==0);
            OVERLAPPED ovl{}; BOOL rc=connectEx(client,target->ai_addr,static_cast<int>(target->ai_addrlen),const_cast<char*>("PING"),4,nullptr,&ovl);
            assert(rc || WSAGetLastError()==WSA_IO_PENDING || WSAGetLastError()==WSAECONNREFUSED);
            ULONG_PTR key=0; LPOVERLAPPED completed=nullptr;
            if(scenario==L"iocp_fail_ex") {
                OVERLAPPED_ENTRY entry{}; ULONG count=0;
                assert(GetQueuedCompletionStatusEx(iocp,&entry,1,&count,10000,FALSE));
                assert(count==1 && entry.Internal!=0 && entry.lpOverlapped==&ovl);
            } else if(scenario==L"iocp_fail") {
                assert(!GetQueuedCompletionStatus(iocp,&bytes,&key,&completed,10000));
                assert(completed==&ovl && GetLastError()==ERROR_CONNECTION_REFUSED);
            } else {
                assert(GetQueuedCompletionStatus(iocp,&bytes,&key,&completed,10000)); assert(completed==&ovl && bytes==4 && key==7);
                DWORD flags=0; assert(WSAGetOverlappedResult(client,&ovl,&bytes,FALSE,&flags) && bytes==4);
                assert(Read(client,4)==std::vector<uint8_t>({'P','O','N','G'}));
            }
        } else {
            assert(connect(client,target->ai_addr,static_cast<int>(target->ai_addrlen))==0);

            bool callback=scenario==L"udp_callback" || scenario==L"udp_immediate_callback";
            if(scenario==L"udp") { iocp=CreateIoCompletionPort(reinterpret_cast<HANDLE>(client.value),nullptr,9,1); assert(iocp); }
            char payload[64]{}; OVERLAPPED ovl{}; DWORD bytes=0,flags=0;
            if(scenario==L"udp_event") ovl.hEvent=CreateEventW(nullptr,TRUE,FALSE,nullptr);
            if(scenario==L"udp_immediate_callback") {
                assert(send(client,"UDP!",4,0)==4);
                assert(WaitForSingleObject(datagramSent,10000)==WAIT_OBJECT_0);
            }
            int rc=0;
            {   // The Winsock contract permits descriptors to go out of scope on return.
                WSABUF buffer{sizeof(payload),payload};
                rc=WSARecv(client,&buffer,1,&bytes,&flags,&ovl,callback?UdpCallback:nullptr);
            }
            assert(rc==0 || WSAGetLastError()==WSA_IO_PENDING);
            if(scenario==L"udp_immediate_callback") assert(rc==0 && udpCallbacks==0);
            else assert(send(client,"UDP!",4,0)==4);
            if(callback) {
                auto start=GetTickCount64();
                while(udpCallbacks==0 && GetTickCount64()-start<10000) SleepEx(50,TRUE);
                assert(udpCallbacks==1 && udpCallbackBytes==4 && !memcmp(payload,"UDP!",4));
                SleepEx(10,TRUE); assert(udpCallbacks==1);
            } else if(scenario==L"udp_event") {
                assert(WaitForSingleObject(ovl.hEvent,10000)==WAIT_OBJECT_0);
                assert(WSAGetOverlappedResult(client,&ovl,&bytes,FALSE,&flags));
                assert(bytes==4 && !memcmp(payload,"UDP!",4)); CloseHandle(ovl.hEvent);
            } else {
                OVERLAPPED_ENTRY entry{}; ULONG count=0;
                assert(GetQueuedCompletionStatusEx(iocp,&entry,1,&count,10000,FALSE));
                assert(count==1 && entry.lpOverlapped==&ovl && entry.dwNumberOfBytesTransferred==4 && !memcmp(payload,"UDP!",4));
                assert(WSAGetOverlappedResult(client,&ovl,&bytes,FALSE,&flags) && bytes==4);
            }
            CloseHandle(datagramSent);
            udpServer.join();
        }
        freeaddrinfo(target);
        assert(closesocket(client.value)==0); client.value=INVALID_SOCKET;
        if(iocp) CloseHandle(iocp);
        server.join();
    }
    FreeLibrary(core); // core remains pinned for outstanding hooks/I/O
}
