#include "Test.hpp"
int wmain(int argc,wchar_t** argv) {
    if(argc>1&&std::wstring(argv[1])==L"--job-grandchild"){Sleep(INFINITE);return 0;}
    if(argc>1&&std::wstring(argv[1])==L"--attach-wait") {
        HANDLE event=OpenEventW(EVENT_MODIFY_STATE,FALSE,argv[2]);if(!event)return 91;SetEvent(event);CloseHandle(event);
        auto start=GetTickCount64();while(!GetModuleHandleW(L"codex_proxy.dll")&&GetTickCount64()-start<15000)Sleep(10);
    }
    HMODULE core=GetModuleHandleW(L"codex_proxy.dll");if(!core)return 90;
    auto wait=reinterpret_cast<DWORD(*)(DWORD)>(GetProcAddress(core,"CodexProxy_WaitReady"));if(!wait||wait(10000)!=1)return 92;
    if(argc>2&&std::wstring(argv[1])==L"--job-parent") {
        wchar_t path[32768]{};GetModuleFileNameW(nullptr,path,32768);std::wstring command=L"\""+std::wstring(path)+L"\" --job-grandchild";
        STARTUPINFOW si{};si.cb=sizeof(si);PROCESS_INFORMATION pi{};
        if(!CreateProcessW(path,command.data(),nullptr,nullptr,FALSE,0,nullptr,nullptr,&si,&pi))return 93;
        std::ofstream(std::filesystem::path(argv[2]))<<pi.dwProcessId;
        CloseHandle(pi.hThread);CloseHandle(pi.hProcess);Sleep(INFINITE);return 0;
    }
    if(argc>1&&std::wstring(argv[1])==L"--pipes") {
        DWORD count=0,written=0;char data[1024];
        while(ReadFile(GetStdHandle(STD_INPUT_HANDLE),data,sizeof(data),&count,nullptr)&&count)if(!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),data,count,&written,nullptr)||written!=count)return 94;
        const char message[]="child-stderr\n";WriteFile(GetStdHandle(STD_ERROR_HANDLE),message,sizeof(message)-1,&written,nullptr);return 37;
    }
    if(argc>1&&std::wstring(argv[1])==L"--attach-wait")return 37;
    Winsock wsa;
    addrinfo hints{};hints.ai_family=AF_INET;hints.ai_socktype=SOCK_STREAM;addrinfo* target=nullptr;
    if(getaddrinfo("launcher-test.invalid","443",&hints,&target))return 70;
    Socket socket(::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP));
    int result=connect(socket,target->ai_addr,static_cast<int>(target->ai_addrlen));freeaddrinfo(target);if(result)return 71;
    if(send(socket,"PING",4,0)!=4)return 72;
    char reply[4]{};int read=0;while(read<4){int n=recv(socket,reply+read,4-read,0);if(n<=0)return 73;read+=n;}
    if(memcmp(reply,"PONG",4))return 74;
    const char output[]="{\"ok\":true}\n";DWORD written=0;WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),output,sizeof(output)-1,&written,nullptr);return 37;
}
