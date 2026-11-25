#include "Test.hpp"
#include "launcher/CliLauncherLogic.hpp"
static std::vector<uint8_t> Read(SOCKET s,size_t count) {
    std::vector<uint8_t> data(count);size_t offset=0;while(offset<count){int n=recv(s,reinterpret_cast<char*>(data.data()+offset),static_cast<int>(count-offset),0);assert(n>0);offset+=n;}return data;
}
struct Handles {std::vector<HANDLE> handles;~Handles(){for(auto h:handles)if(h&&h!=INVALID_HANDLE_VALUE)CloseHandle(h);}HANDLE Keep(HANDLE h){handles.push_back(h);return h;}};
int wmain(int argc,wchar_t** argv) {
    assert(argc==4);Winsock wsa;TestDirectory tmp;Handles handles;std::wstring mode=argv[3];
    HANDLE job=handles.Keep(CreateJobObjectW(nullptr,nullptr));assert(job);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE|JOB_OBJECT_LIMIT_BREAKAWAY_OK;
    assert(SetInformationJobObject(job,JobObjectExtendedLimitInformation,&limits,sizeof(limits)));
    SECURITY_ATTRIBUTES sa{sizeof(sa),nullptr,TRUE};
    auto outPath=tmp.path/L"stdout.bin",errPath=tmp.path/L"stderr.txt";
    HANDLE output=handles.Keep(CreateFileW(outPath.c_str(),GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,&sa,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr));
    HANDLE error=handles.Keep(CreateFileW(errPath.c_str(),GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,&sa,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr));
    assert(output!=INVALID_HANDLE_VALUE&&error!=INVALID_HANDLE_VALUE);
    HANDLE inputRead=nullptr,inputWrite=nullptr;assert(CreatePipe(&inputRead,&inputWrite,&sa,0));handles.Keep(inputRead);SetHandleInformation(inputWrite,HANDLE_FLAG_INHERIT,0);
    auto spawn=[&](const std::filesystem::path& exe,const std::vector<std::wstring>& args){
        auto command=Launcher::Command(exe,args);STARTUPINFOW si{};si.cb=sizeof(si);si.dwFlags=STARTF_USESTDHANDLES;si.hStdInput=inputRead;si.hStdOutput=output;si.hStdError=error;
        PROCESS_INFORMATION pi{};assert(CreateProcessW(exe.c_str(),command.data(),nullptr,nullptr,TRUE,CREATE_SUSPENDED,nullptr,nullptr,&si,&pi));
        handles.Keep(pi.hProcess);handles.Keep(pi.hThread);assert(AssignProcessToJobObject(job,pi.hProcess));assert(ResumeThread(pi.hThread)==1);return pi;
    };
    auto configPath=tmp.path/L"config space.json";uint16_t port=0;Socket listener;std::thread server;
    bool network=mode==L"socks5"||mode==L"http";
    if(network) {
        listener.value=Listen(&port);
        server=std::thread([&]{Socket peer(accept(listener,nullptr,nullptr));
            if(mode==L"socks5") {
                auto greeting=Read(peer,2);assert(greeting[0]==5);Read(peer,greeting[1]);assert(send(peer,"\5\0",2,0)==2);
                auto head=Read(peer,4);assert(head[1]==1&&head[3]==3);auto length=Read(peer,1)[0];auto name=Read(peer,length);assert(std::string(name.begin(),name.end())=="launcher-test.invalid");Read(peer,2);
                const char reply[]={5,0,0,1,0,0,0,0,0,0};assert(send(peer,reply,sizeof(reply),0)==sizeof(reply));
            }else{
                std::string request;while(request.find("\r\n\r\n")==std::string::npos)request+=static_cast<char>(Read(peer,1)[0]);
                assert(request.find("CONNECT launcher-test.invalid:443 HTTP/1.1\r\n")==0);
                assert(request.find("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n")!=std::string::npos);
                std::string reply="HTTP/1.1 200 OK\r\n\r\n";assert(send(peer,reply.data(),static_cast<int>(reply.size()),0)==reply.size());
            }
            assert(Read(peer,4)==std::vector<uint8_t>({'P','I','N','G'}));assert(send(peer,"PONG",4,0)==4);
        });
    }
    nlohmann::json config={{"proxy",{{"port",network?port:0},{"type",mode==L"http"?"http":"socks5"},{"username",mode==L"http"?"user":""},{"password",mode==L"http"?"pass":""}}},{"target_processes",nlohmann::json::array()}};
    if(mode==L"failure")config["proxy"]["port"]="invalid";
    JsonFile(configPath,config);
    std::vector<std::wstring> args={L"--config",configPath.wstring(),L"--exec",argv[2]};
    PROCESS_INFORMATION direct{};
    if(mode==L"attach") {
        auto name=L"Local\\CodexProxy_TestReady_"+std::to_wstring(GetCurrentProcessId());HANDLE ready=handles.Keep(CreateEventW(nullptr,TRUE,FALSE,name.c_str()));
        direct=spawn(argv[2],{L"--attach-wait",name});assert(WaitForSingleObject(ready,10000)==WAIT_OBJECT_0);
        args={L"--config",configPath.wstring(),L"--attach",std::to_wstring(direct.dwProcessId)};
    } else if(mode==L"pipes")args.push_back(L"--pipes");
    else if(mode==L"job"){args.push_back(L"--job-parent");args.push_back((tmp.path/L"grandchild.pid").wstring());}
    auto wrapper=spawn(argv[1],args);
    std::string input="{\"jsonrpc\":\"2.0\"}\n";input.append("\0binary",7);DWORD written=0;
    if(mode==L"pipes")assert(WriteFile(inputWrite,input.data(),static_cast<DWORD>(input.size()),&written,nullptr));CloseHandle(inputWrite);
    if(mode==L"job") {
        auto marker=tmp.path/L"grandchild.pid";DWORD pid=0;auto started=GetTickCount64();
        while(GetTickCount64()-started<10000){std::ifstream file(marker);if(file>>pid)break;Sleep(10);}assert(pid);
        HANDLE grandchild=handles.Keep(OpenProcess(SYNCHRONIZE,FALSE,pid));assert(grandchild);
        assert(TerminateProcess(wrapper.hProcess,99));assert(WaitForSingleObject(grandchild,10000)==WAIT_OBJECT_0);return 0;
    }
    assert(WaitForSingleObject(wrapper.hProcess,20000)==WAIT_OBJECT_0);DWORD code=0;assert(GetExitCodeProcess(wrapper.hProcess,&code));
    assert(code==(mode==L"failure"?125u:(mode==L"attach"?0u:37u)));
    if(mode==L"attach"){assert(WaitForSingleObject(direct.hProcess,10000)==WAIT_OBJECT_0);assert(GetExitCodeProcess(direct.hProcess,&code)&&code==37);}
    if(network)server.join();
    auto readFile=[](const std::filesystem::path& path){std::ifstream file(path,std::ios::binary);return std::string(std::istreambuf_iterator<char>(file),{});};
    auto stdoutText=readFile(outPath),stderrText=readFile(errPath);
    if(mode==L"pipes"){assert(stdoutText==input);assert(stderrText=="child-stderr\n");}
    else if(network){assert(stdoutText=="{\"ok\":true}\n");assert(stderrText.empty());}
    else assert(stdoutText.empty());
}
