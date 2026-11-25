#include "Test.hpp"
// Compile the actual detours into an isolated test executable. Function-pointer
// providers are controlled here; no hooks are installed in this or other apps.
#include "../src/hooks/Hooks.cpp"
#include <iostream>

static sockaddr_storage connectedAddress{};
static int connectCalls=0;
static int WSAAPI CaptureConnect(SOCKET,const sockaddr* address,int length) {
    assert(length<=sizeof(connectedAddress));
    memcpy(&connectedAddress,address,length); ++connectCalls; return 0;
}
static int WSAAPI CaptureWSAConnect(SOCKET s,const sockaddr* address,int length,LPWSABUF,LPWSABUF,LPQOS,LPQOS) {
    return CaptureConnect(s,address,length);
}
static int WSAAPI PublicResolver(PCSTR name,PCSTR service,const ADDRINFOA* hints,PADDRINFOA* result) {
    if(std::string(name)=="direct-review.invalid")
        name=hints && hints->ai_family==AF_INET6?"::ffff:93.184.216.34":"93.184.216.34";
    return getaddrinfo(name,service,hints,result);
}
static void DnsDirectIdentity() {
    auto& config=Core::Config::Instance();
    assert(config.Parse({{"proxy",{{"port",7890}}},{"rules",{{"allowed_ports",nlohmann::json::array()},
        {"routing",{{"default_action","proxy"},{"use_default_private",false},{"rules",{
            {{"domains",{"direct-review.invalid"}},{"action","direct"}}}}}}}}}));
    fpGetAddrInfo=PublicResolver; fpConnect=CaptureConnect; fpWSAConnect=CaptureWSAConnect;
    for(int family:{AF_INET,AF_INET6}) {
        assert(Hooks::ShouldFakeDns("direct-review.invalid",443,family,0,SOCK_STREAM));
        addrinfo hints{}; hints.ai_family=family; hints.ai_socktype=SOCK_STREAM;
        addrinfo* result=nullptr;
        assert(DetourGetAddrInfo("direct-review.invalid","443",&hints,&result)==0);
        std::string host; uint16_t port=0;
        assert(ResolveOriginalTarget(result->ai_addr,&host,&port) && host=="direct-review.invalid" && port==443);
        Socket socket(::socket(family,SOCK_STREAM,IPPROTO_TCP)); assert(socket.value!=INVALID_SOCKET);
        int before=connectCalls;
        assert(PerformProxyConnect(socket,result->ai_addr,static_cast<int>(result->ai_addrlen),false)==0);
        assert(connectCalls==before+1);
        std::string ip; bool v6=false; assert(SockaddrToIp(reinterpret_cast<sockaddr*>(&connectedAddress),&ip,&v6));
        assert(ip=="93.184.216.34" || ip=="::ffff:93.184.216.34");
        freeaddrinfo(result);
    }
    assert(!Hooks::ShouldFakeDns("localhost",1455,AF_INET,0,SOCK_STREAM));
    assert(!Hooks::ShouldFakeDns("127.0.0.1",1457,AF_INET,0,SOCK_STREAM));
}

static LPOVERLAPPED completionPointer=nullptr;
static BOOL WINAPI CompletePacket(HANDLE,LPDWORD bytes,PULONG_PTR key,LPOVERLAPPED* ovl,DWORD) {
    *bytes=17; *key=1; *ovl=completionPointer; return TRUE;
}
static int WSAAPI PlainSend(SOCKET,LPWSABUF,DWORD,LPDWORD bytes,DWORD,LPWSAOVERLAPPED,LPWSAOVERLAPPED_COMPLETION_ROUTINE) { if(bytes)*bytes=17;return 0; }
static int WSAAPI PlainRecv(SOCKET,LPWSABUF,DWORD,LPDWORD bytes,LPDWORD,LPWSAOVERLAPPED,LPWSAOVERLAPPED_COMPLETION_ROUTINE) { if(bytes)*bytes=17;return 0; }
static int WSAAPI PlainSendTo(SOCKET s,LPWSABUF b,DWORD n,LPDWORD bytes,DWORD f,const sockaddr*,int,LPWSAOVERLAPPED o,LPWSAOVERLAPPED_COMPLETION_ROUTINE c) { return PlainSend(s,b,n,bytes,f,o,c); }
static int WSAAPI PlainRecvFrom(SOCKET s,LPWSABUF b,DWORD n,LPDWORD bytes,LPDWORD f,sockaddr*,LPINT,LPWSAOVERLAPPED o,LPWSAOVERLAPPED_COMPLETION_ROUTINE c) { return PlainRecv(s,b,n,bytes,f,o,c); }
static BOOL PASCAL PlainConnectEx(SOCKET,const sockaddr*,int,PVOID,DWORD,LPDWORD bytes,LPOVERLAPPED) { if(bytes)*bytes=17;return TRUE; }
static void ConnectReuse() {
    Core::Config::Instance().proxy.port=0;
    fpWSASend=PlainSend; fpWSARecv=PlainRecv; fpWSASendTo=PlainSendTo; fpWSARecvFrom=PlainRecvFrom;
    fpConnectEx=PlainConnectEx; fpGetQueuedCompletionStatus=CompletePacket;
    Socket socket(::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP));
    OVERLAPPED ovl{}; completionPointer=&ovl;
    char data[32]{}; WSABUF buffer{sizeof(data),data}; DWORD bytes=0,flags=0;
    sockaddr_in address{}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK); address.sin_port=htons(1455);
    for(int operation=0;operation<5;++operation) {
        ConnectExContext context{}; context.sock=socket; context.completion->done=true;
        context.completion->success=true; context.completion->bytes=999;
        std::weak_ptr<ConnectCompletion> lifetime=context.completion;
        SaveConnectExContext(&ovl,context); context.completion.reset();
        if(operation==0) assert(DetourWSARecv(socket,&buffer,1,&bytes,&flags,&ovl,nullptr)==0);
        if(operation==1) assert(DetourWSASend(socket,&buffer,1,&bytes,0,&ovl,nullptr)==0);
        if(operation==2) assert(DetourWSARecvFrom(socket,&buffer,1,&bytes,&flags,nullptr,nullptr,&ovl,nullptr)==0);
        if(operation==3) assert(DetourWSASendTo(socket,&buffer,1,&bytes,0,nullptr,0,&ovl,nullptr)==0);
        if(operation==4) assert(DetourConnectEx(socket,reinterpret_cast<sockaddr*>(&address),sizeof(address),nullptr,0,&bytes,&ovl));
        assert(!FindConnectExContext(&ovl,nullptr) && lifetime.expired());
        ULONG_PTR key=0; LPOVERLAPPED completed=nullptr;
        assert(DetourGetQueuedCompletionStatus(nullptr,&bytes,&key,&completed,0) && bytes==17 && completed==&ovl);
    }
    ConnectExContext pending{}; pending.sock=socket; SaveConnectExContext(&ovl,pending);
    BeginOverlappedOperation(&ovl); assert(FindConnectExContext(&ovl,nullptr));
    DropConnectExContext(&ovl);
}

static std::shared_ptr<UdpOverlappedRecvCtx> ReceiveContext(SOCKET socket,WSABUF buffer,size_t allocation=1048576) {
    auto context=std::make_shared<UdpOverlappedRecvCtx>(); context->sock=socket;
    context->userBuffers={buffer}; context->userBufs=context->userBuffers.data(); context->userBufCount=1;
    assert(Network::Socks5Udp::Wrap("203.0.113.1",443,reinterpret_cast<const uint8_t*>("hello"),5,&context->recvBuf));
    context->recvBuf.reserve(allocation); return context;
}
static void UdpRelease() {
    char data[32]{}; WSABUF buffer{sizeof(data),data}; DWORD bytes=0; int error=0;
    std::vector<OVERLAPPED> operations(256);
    for(auto& ovl:operations) {
        auto context=ReceiveContext(123,buffer); auto encoded=static_cast<DWORD>(context->recvBuf.size());
        std::weak_ptr<UdpOverlappedRecvCtx> lifetime=context;
        g_udpOvlRecv[&ovl]=context; context.reset();
        assert(HandleUdpOverlappedCompletion(&ovl,encoded,&bytes,&error,true));
        assert(bytes==5 && error==0 && lifetime.expired());
    }
    assert(g_udpOvlRecv.empty() && g_udpCompleted.empty());
    OVERLAPPED immediate{}; auto context=ReceiveContext(123,buffer);
    auto encoded=static_cast<DWORD>(context->recvBuf.size()); g_udpOvlRecv[&immediate]=context;
    assert(HandleUdpOverlappedCompletion(&immediate,encoded,&bytes,&error));
    assert(context->recvBuf.capacity()==0 && context->userBuffers.capacity()==0 && context->userBufs==nullptr);
    assert(g_udpOvlRecv.empty() && g_udpCompleted.size()==1);
    assert(HandleUdpOverlappedCompletion(&immediate,encoded,&bytes,&error,true) && bytes==5);
    assert(g_udpCompleted.empty());
    OVERLAPPED cancelled{}; context=ReceiveContext(456,buffer);
    std::weak_ptr<UdpOverlappedRecvCtx> lifetime=context; g_udpOvlRecv[&cancelled]=context; context.reset();
    CleanupUdpOverlappedBySocket(456); assert(!lifetime.expired()); // provider can still write until cancelled completion
    DropUdpOverlappedContext(&cancelled); assert(lifetime.expired());
}

static sockaddr_in LoopbackAddress(SOCKET socket) {
    sockaddr_in address{}; int length=sizeof(address);
    assert(getsockname(socket,reinterpret_cast<sockaddr*>(&address),&length)==0); return address;
}
static void BindUdp(SOCKET socket) {
    sockaddr_in address{}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    assert(bind(socket,reinterpret_cast<sockaddr*>(&address),sizeof(address))==0);
    DWORD timeout=2000; assert(setsockopt(socket,SOL_SOCKET,SO_RCVTIMEO,reinterpret_cast<char*>(&timeout),sizeof(timeout))==0);
}
static void AddRelay(SOCKET client,const sockaddr_in& relay) {
    UdpProxyContext context{}; context.udpSock=client;
    memcpy(&context.relayAddr,&relay,sizeof(relay)); context.relayAddrLen=sizeof(relay);
    g_udpProxy[client]=context;
}
static void UdpUnconnected() {
    auto& config=Core::Config::Instance();
    assert(config.Parse({{"proxy",{{"port",7890}}},{"rules",{{"udp_mode","proxy"},
        {"routing",{{"use_default_private",false},{"default_action","proxy"}}}}}}));
    fpSendTo=sendto; fpWSASendTo=WSASendTo; fpRecvFrom=recvfrom; fpWSARecvFrom=WSARecvFrom;
    fpConnect=connect; fpCloseSocket=closesocket; fpWSAGetOverlappedResult=WSAGetOverlappedResult;
    for(int operation=0;operation<3;++operation) {
        Socket client(socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP)),relay(socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP)),local(socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP));
        BindUdp(client); BindUdp(relay); BindUdp(local);
        auto relayAddress=LoopbackAddress(relay),localAddress=LoopbackAddress(local); AddRelay(client,relayAddress);
        sockaddr_in target{}; target.sin_family=AF_INET; target.sin_port=htons(443); inet_pton(AF_INET,"203.0.113.1",&target.sin_addr);
        char payload[]="UDP!"; WSABUF buffer{4,payload}; DWORD bytes=0;
        OVERLAPPED ovl{}; ovl.hEvent=CreateEventW(nullptr,TRUE,FALSE,nullptr); assert(ovl.hEvent);
        if(operation==0) assert(DetourSendTo(client,payload,4,0,reinterpret_cast<sockaddr*>(&target),sizeof(target))==4);
        else {
            auto overlapped=operation==2?&ovl:nullptr;
            int rc=DetourWSASendTo(client,&buffer,1,&bytes,0,reinterpret_cast<sockaddr*>(&target),sizeof(target),overlapped,nullptr);
            assert(rc==0 || (rc==SOCKET_ERROR && WSAGetLastError()==WSA_IO_PENDING));
            if(overlapped) { DWORD flags=0;assert(DetourWSAGetOverlappedResult(client,&ovl,&bytes,TRUE,&flags)); }
            assert(bytes==4);
        }
        sockaddr_storage peer{}; int length=sizeof(peer);
        assert(getpeername(client,reinterpret_cast<sockaddr*>(&peer),&length)==SOCKET_ERROR && WSAGetLastError()==WSAENOTCONN);
        assert(!TryGetUdpProxyDefaultTarget(client,nullptr,nullptr));
        char packet[512]{}; sockaddr_in source{}; length=sizeof(source);
        int count=recvfrom(relay,packet,sizeof(packet),0,reinterpret_cast<sockaddr*>(&source),&length); assert(count==14);
        assert(sendto(relay,packet,count,0,reinterpret_cast<sockaddr*>(&source),length)==count);
        if(operation==0) assert(DetourSendTo(client,"LOCAL",5,0,reinterpret_cast<sockaddr*>(&localAddress),sizeof(localAddress))==5);
        else { WSABUF direct{5,const_cast<char*>("LOCAL")}; assert(DetourWSASendTo(client,&direct,1,&bytes,0,reinterpret_cast<sockaddr*>(&localAddress),sizeof(localAddress),nullptr,nullptr)==0 && bytes==5); }
        length=sizeof(source); assert(recvfrom(local,packet,sizeof(packet),0,reinterpret_cast<sockaddr*>(&source),&length)==5);
        assert(sendto(local,"LOCAL",5,0,reinterpret_cast<sockaddr*>(&source),length)==5);
        // Both relay and direct replies must be accepted and correctly decoded.
        bool sawProxy=false,sawLocal=false;
        for(int i=0;i<2;++i) {
            char reply[32]{}; length=sizeof(source);
            int size=DetourRecvFrom(client,reply,sizeof(reply),0,reinterpret_cast<sockaddr*>(&source),&length);
            if(size==4) { assert(!memcmp(reply,"UDP!",4)); sawProxy=true; }
            else { assert(size==5 && !memcmp(reply,"LOCAL",5) && source.sin_port==localAddress.sin_port); sawLocal=true; }
        }
        assert(sawProxy && sawLocal && !IsSocketConnected(client));
        CleanupUdpProxyContext(client); CloseHandle(ovl.hEvent);
    }
}

static std::vector<uint8_t> immediatePacket;
static sockaddr_in immediateRelay{};
static int WSAAPI ImmediateReceive(SOCKET,LPWSABUF buffers,DWORD count,LPDWORD bytes,LPDWORD,
    sockaddr* from,LPINT length,LPWSAOVERLAPPED ovl,LPWSAOVERLAPPED_COMPLETION_ROUTINE) {
    assert(count==1 && buffers[0].len>=immediatePacket.size());
    memcpy(buffers[0].buf,immediatePacket.data(),immediatePacket.size());
    if(bytes)*bytes=static_cast<DWORD>(immediatePacket.size());
    memcpy(from,&immediateRelay,sizeof(immediateRelay)); *length=sizeof(immediateRelay);
    ovl->Internal=0; ovl->InternalHigh=immediatePacket.size(); return 0;
}
static int WSAAPI ImmediatePlainReceive(SOCKET s,LPWSABUF buffers,DWORD count,LPDWORD bytes,LPDWORD flags,
    LPWSAOVERLAPPED ovl,LPWSAOVERLAPPED_COMPLETION_ROUTINE callback) {
    sockaddr_storage source{}; int length=sizeof(source);
    return ImmediateReceive(s,buffers,count,bytes,flags,reinterpret_cast<sockaddr*>(&source),&length,ovl,callback);
}
static void UdpImmediateErrors() {
    auto& config=Core::Config::Instance(); assert(config.Parse({{"proxy",{{"port",7890}}},{"rules",{{"udp_mode","proxy"}}}}));
    fpWSARecvFrom=ImmediateReceive; fpWSARecv=ImmediatePlainReceive;
    Socket socket(::socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP));
    immediateRelay.sin_family=AF_INET; immediateRelay.sin_port=htons(9876); immediateRelay.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    AddRelay(socket,immediateRelay);
    for(bool byFrom:{false,true}) for(bool malformed:{false,true}) {
        if(malformed) immediatePacket={0,0};
        else assert(Network::Socks5Udp::Wrap("203.0.113.1",443,reinterpret_cast<const uint8_t*>("hello"),5,&immediatePacket));
        OVERLAPPED ovl{}; char output[2]{}; WSABUF buffer{sizeof(output),output}; DWORD bytes=99,flags=0;
        sockaddr_storage source{}; int length=sizeof(source);
        int rc=byFrom?DetourWSARecvFrom(socket,&buffer,1,&bytes,&flags,reinterpret_cast<sockaddr*>(&source),&length,&ovl,nullptr):
            DetourWSARecv(socket,&buffer,1,&bytes,&flags,&ovl,nullptr);
        int expected=malformed?WSAECONNRESET:WSAEMSGSIZE;
        assert(rc==SOCKET_ERROR && WSAGetLastError()==expected && bytes==(malformed?0u:2u));
        if(!malformed) assert(!memcmp(output,"he",2));
        assert(g_udpOvlRecv.empty());
        int error=0; assert(HandleUdpOverlappedCompletion(&ovl,999,&bytes,&error,true) && error==expected);
    }
    assert(g_udpCompleted.empty()); CleanupUdpProxyContext(socket);
}

static void ByNameLocal() {
    auto& config=Core::Config::Instance();
    assert(config.Parse({{"proxy",{{"host","127.0.0.1"},{"port",9}}},{"rules",{{"routing",{
        {"use_default_private",false},{"default_action","proxy"},{"rules",{
            {{"ip_cidrs_v4",{"0.0.0.0/0"}},{"ip_cidrs_v6",{"::/0"}},{"action","proxy"}}}}}}}}}));
    fpWSAConnectByNameA=WSAConnectByNameA; fpWSAConnectByNameW=WSAConnectByNameW;
    fpConnect=CaptureConnect; fpWSAConnect=CaptureWSAConnect; fpCloseSocket=closesocket;
    PMIB_UNICASTIPADDRESS_TABLE table=nullptr; assert(GetUnicastIpAddressTable(AF_UNSPEC,&table)==NO_ERROR);
    int checked=0;
    for(ULONG i=0;i<table->NumEntries;++i) {
        auto address=table->Table[i].Address;
        if(address.si_family!=AF_INET && address.si_family!=AF_INET6)continue;
        sockaddr* raw=reinterpret_cast<sockaddr*>(&address);
        if(Network::IsLoopbackSockaddr(raw,address.si_family==AF_INET?sizeof(sockaddr_in):sizeof(sockaddr_in6))) continue;
        std::string ip; bool v6=false; assert(SockaddrToIp(raw,&ip,&v6));
        if(v6 && address.Ipv6.sin6_scope_id) ip+="%"+std::to_string(address.Ipv6.sin6_scope_id);
        for(bool wide:{false,true}) {
            Socket socket(::socket(address.si_family,SOCK_STREAM,IPPROTO_TCP)); assert(socket.value!=INVALID_SOCKET);
            // Bind first so the provider can fill the optional local output even
            // though CaptureConnect deliberately avoids making a real connection.
            sockaddr_storage bound{}; bound.ss_family=address.si_family;
            assert(bind(socket,reinterpret_cast<sockaddr*>(&bound),v6?sizeof(sockaddr_in6):sizeof(sockaddr_in))==0);
            sockaddr_storage local{},remote{}; DWORD ll=sizeof(local),rl=sizeof(remote); int before=connectCalls;
            std::wstring node(ip.begin(),ip.end()),service=L"1457";
            BOOL ok=wide?DetourWSAConnectByNameW(socket,node.data(),service.data(),&ll,reinterpret_cast<sockaddr*>(&local),&rl,reinterpret_cast<sockaddr*>(&remote),nullptr,nullptr):
                DetourWSAConnectByNameA(socket,ip.c_str(),"1455",&ll,reinterpret_cast<sockaddr*>(&local),&rl,reinterpret_cast<sockaddr*>(&remote),nullptr,nullptr);
            assert(ok && connectCalls==before+1 && IsLocalBypassSocket(socket));
            assert(Network::IsLocalSockaddr(reinterpret_cast<sockaddr*>(&connectedAddress),static_cast<int>(rl)));
            DWORD timeout=0; int length=sizeof(timeout);
            assert(getsockopt(socket,SOL_SOCKET,SO_SNDTIMEO,reinterpret_cast<char*>(&timeout),&length)==0 && timeout==0);
            SetLocalBypassSocket(socket,false); ++checked;
        }
    }
    FreeMibTable(table);
    if(!checked) std::cout << "No non-loopback adapter assigned; adapter-specific cases skipped.\n";
}
int main(int argc,char** argv) {
    assert(argc==2); Winsock winsock; TestDirectory temporary;
    Core::Logger::SetEnabled(false); Core::Config::Instance().loadedPath=temporary.path/L"config.json";
    std::string scenario=argv[1];
    if(scenario=="dns_direct") DnsDirectIdentity();
    else if(scenario=="connect_reuse") ConnectReuse();
    else if(scenario=="udp_release") UdpRelease();
    else if(scenario=="udp_unconnected") UdpUnconnected();
    else if(scenario=="udp_immediate") UdpImmediateErrors();
    else if(scenario=="byname_local") ByNameLocal();
    else assert(false);
}
