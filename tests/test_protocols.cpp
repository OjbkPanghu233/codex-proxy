#include "Test.hpp"
#include "network/Socks5.hpp"
#include "network/Socks5Udp.hpp"
#include "network/HttpConnect.hpp"
#include "network/SocketWrapper.hpp"
static std::vector<uint8_t> Read(SOCKET s, size_t count) {
    std::vector<uint8_t> bytes(count); size_t position = 0;
    while (position < count) { int n = recv(s, reinterpret_cast<char*>(bytes.data()+position), static_cast<int>(count-position),0); assert(n>0); position+=n; }
    return bytes;
}
static void Write(SOCKET s, std::initializer_list<uint8_t> bytes) {
    for (auto ch : bytes) { char c = static_cast<char>(ch); assert(send(s,&c,1,0)==1); }
}
int main() {
    Winsock wsa;
    auto& config = Core::Config::Instance();
    config.proxy.username="user"; config.proxy.password="pass";
    uint16_t port=0;
    {
        Socket listener(Listen(&port));
        std::thread server([&] {
            Socket peer(accept(listener,nullptr,nullptr));
            assert(Read(peer,4)==std::vector<uint8_t>({5,2,0,2}));
            Write(peer,{5,2});
            assert(Read(peer,11)==std::vector<uint8_t>({1,4,'u','s','e','r',4,'p','a','s','s'}));
            Write(peer,{1,0});
            assert(Read(peer,4)==std::vector<uint8_t>({5,1,0,3}));
            auto length=Read(peer,1)[0]; auto host=Read(peer,length);
            assert(std::string(host.begin(),host.end())=="api.example.test");
            assert(Read(peer,2)==std::vector<uint8_t>({1,187}));
            Write(peer,{5,0,0,1,0,0,0,0,0,0,'X'});
        });
        Socket client(LoopbackConnect(port));
        assert(Network::Socks5Client::Handshake(client,"api.example.test",443));
        assert(Read(client,1)[0]=='X'); server.join();
    }
    {
        Socket listener(Listen(&port)); std::string request;
        std::thread server([&] {
            Socket peer(accept(listener,nullptr,nullptr));
            while (request.find("\r\n\r\n")==std::string::npos) request+=static_cast<char>(Read(peer,1)[0]);
            std::string response="HTTP/1.1 200 Connection Established\r\n\r\nTLS";
            assert(send(peer,response.data(),static_cast<int>(response.size()),0)==response.size());
        });
        Socket client(LoopbackConnect(port));
        assert(Network::HttpConnectClient::Handshake(client,"2001:db8::1",443));
        assert(Read(client,3)==std::vector<uint8_t>({'T','L','S'})); server.join();
        assert(request=="CONNECT [2001:db8::1]:443 HTTP/1.1\r\nHost: [2001:db8::1]:443\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n");
        assert(!Network::HttpConnectClient::Handshake(client,"evil\r\nInjected: yes",443));
    }
    {
        Socket listener(Listen(&port));
        std::thread server([&] {
            Socket peer(accept(listener,nullptr,nullptr)); Read(peer,4); Write(peer,{5,2}); Read(peer,11); Write(peer,{2,0});
        });
        Socket client(LoopbackConnect(port));
        assert(!Network::Socks5Client::Authenticate(client,config.proxy,1000,1000)); server.join();
    }
    {
        Socket listener(Listen(&port));
        std::thread server([&] { Socket peer(accept(listener,nullptr,nullptr)); Sleep(180); });
        Socket client(LoopbackConnect(port));
        uint8_t byte{}; auto start=GetTickCount64();
        assert(!Network::SocketIo::RecvExact(client,&byte,1,50));
        assert(WSAGetLastError()==WSAETIMEDOUT && GetTickCount64()-start<500);
        int original=0; int size=sizeof(original); getsockopt(client,SOL_SOCKET,SO_RCVTIMEO,reinterpret_cast<char*>(&original),&size);
        { Network::SocketWrapper wrapper(client); wrapper.SetTimeouts(123,456); }
        int restored=-1; getsockopt(client,SOL_SOCKET,SO_RCVTIMEO,reinterpret_cast<char*>(&restored),&size); assert(restored==original);
        server.join();
    }
    {
        config.proxy.username.clear(); config.proxy.password.clear();
        Socket listener(Listen(&port));
        std::thread server([&] {
            Socket peer(accept(listener,nullptr,nullptr));
            assert(Read(peer,3)==std::vector<uint8_t>({5,1,0})); Write(peer,{5,0});
            assert(Read(peer,10)[1]==3);
            Write(peer,{5,0,0,3,9,'l','o','c','a','l','h','o','s','t',0x14,0xe9});
        });
        Socket client(LoopbackConnect(port)); Network::Socks5Udp::UdpAssociateResult result{};
        assert(Network::Socks5Udp::UdpAssociate(client,nullptr,0,&result));
        assert(result.relayAddr.ss_family==AF_INET);
        auto& address=*reinterpret_cast<sockaddr_in*>(&result.relayAddr);
        assert(ntohs(address.sin_port)==5353 && address.sin_addr.s_addr==htonl(INADDR_LOOPBACK));
        server.join();
    }
    std::vector<uint8_t> packet;
    for (auto host : {"192.0.2.1","2001:db8::1","x"}) {
        assert(Network::Socks5Udp::Wrap(host,443,reinterpret_cast<const uint8_t*>("hello"),5,&packet));
        Network::Socks5Udp::UnwrapResult decoded{};
        assert(Network::Socks5Udp::Unwrap(packet.data(),packet.size(),&decoded));
        assert(decoded.payloadLen==5 && !memcmp(decoded.payload,"hello",5));
        packet[2]=1; assert(!Network::Socks5Udp::Unwrap(packet.data(),packet.size(),&decoded));
    }
    assert(!Network::Socks5Udp::Wrap("",443,nullptr,0,&packet));
    assert(!Network::Socks5Udp::Wrap("x",443,nullptr,1,&packet));
}
