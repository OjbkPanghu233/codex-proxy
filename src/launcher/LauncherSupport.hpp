#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <appmodel.h>
#include <shellapi.h>
#include <filesystem>
#include <map>
#include <set>
#include <vector>
#include <fstream>
#include "CliLauncherLogic.hpp"
#include "../core/Config.hpp"
#include "../core/LaunchRequest.hpp"
#include "../injection/ProcessInjector.hpp"
#include "../hooks/ProcessName.hpp"
namespace Launcher {
struct Handle {
    HANDLE value=nullptr;
    explicit Handle(HANDLE h=nullptr):value(h){}
    ~Handle(){ if(value && value!=INVALID_HANDLE_VALUE) CloseHandle(value); }
    Handle(const Handle&)=delete; Handle& operator=(const Handle&)=delete;
    operator HANDLE()const{return value;}
};
inline std::string Utf8(const std::wstring& value) {
    if(value.empty())return {};
    int count=WideCharToMultiByte(CP_UTF8,0,value.data(),static_cast<int>(value.size()),nullptr,0,nullptr,nullptr);
    std::string result(count,'\0'); WideCharToMultiByte(CP_UTF8,0,value.data(),static_cast<int>(value.size()),result.data(),count,nullptr,nullptr); return result;
}
inline std::wstring Wide(const std::string& value) {
    if(value.empty())return {};
    int count=MultiByteToWideChar(CP_UTF8,0,value.data(),static_cast<int>(value.size()),nullptr,0);
    std::wstring result(count,L'\0'); MultiByteToWideChar(CP_UTF8,0,value.data(),static_cast<int>(value.size()),result.data(),count);return result;
}
inline void Stderr(const std::wstring& message) {
    HANDLE handle=GetStdHandle(STD_ERROR_HANDLE); if(!handle||handle==INVALID_HANDLE_VALUE)return;
    DWORD mode=0,written=0; auto line=message+L"\r\n";
    if(GetConsoleMode(handle,&mode)) WriteConsoleW(handle,line.data(),static_cast<DWORD>(line.size()),&written,nullptr);
    else { auto text=Utf8(line); WriteFile(handle,text.data(),static_cast<DWORD>(text.size()),&written,nullptr); }
}
inline bool File(const std::filesystem::path& path) {
    if(path.empty())return false;
    DWORD flags=GetFileAttributesW(path.c_str()); return flags!=INVALID_FILE_ATTRIBUTES && !(flags&FILE_ATTRIBUTE_DIRECTORY);
}
inline std::filesystem::path ProcessImage(HANDLE process) {
    std::wstring buffer(32768,L'\0'); DWORD count=static_cast<DWORD>(buffer.size());
    if(!QueryFullProcessImageNameW(process,0,buffer.data(),&count))return {};
    buffer.resize(count);return buffer;
}
inline std::filesystem::path ResolveExecutable(const std::filesystem::path& path) {
    if(File(path))return std::filesystem::absolute(path);
    if(path.has_parent_path())return {};
    wchar_t found[32768]{}; DWORD count=SearchPathW(nullptr,path.c_str(),L".exe",32768,found,nullptr);
    return count && count<32768 && File(found)?std::filesystem::path(found):std::filesystem::path();
}
inline std::vector<std::filesystem::path> Packages() {
    std::vector<std::filesystem::path> result;
    UINT32 count=0,length=0;
    LONG error=GetPackagesByPackageFamily(L"OpenAI.Codex_2p2nqsd0c76g0",&count,nullptr,&length,nullptr);
    if(error!=ERROR_INSUFFICIENT_BUFFER||!count)return result;
    std::vector<PWSTR> names(count);std::vector<wchar_t> buffer(length);
    if(GetPackagesByPackageFamily(L"OpenAI.Codex_2p2nqsd0c76g0",&count,names.data(),&length,buffer.data())!=ERROR_SUCCESS)return result;
    for(UINT32 i=0;i<count;++i) {
        UINT32 size=0; if(GetPackagePathByFullName(names[i],&size,nullptr)!=ERROR_INSUFFICIENT_BUFFER)continue;
        std::vector<wchar_t> path(size);
        if(GetPackagePathByFullName(names[i],&size,path.data())!=ERROR_SUCCESS)continue;
        result.push_back(std::filesystem::path(path.data())/L"app/ChatGPT.exe");
        result.push_back(std::filesystem::path(path.data())/L"app/Codex.exe");
    }
    return result;
}
inline CliLocations Locations() {
    CliLocations env;
    env.overrideExe=Core::Environment(L"CODEX_PROXY_TARGET_EXE");env.appData=Core::Environment(L"APPDATA");
    env.localData=Core::Environment(L"LOCALAPPDATA");env.profile=Core::Environment(L"USERPROFILE");env.bunInstall=Core::Environment(L"BUN_INSTALL");env.pnpmHome=Core::Environment(L"PNPM_HOME");
    auto path=Core::Environment(L"PATH");size_t start=0;
    while(start<=path.size()){auto end=path.find(L';',start);auto entry=path.substr(start,end-start);if(entry.size()>1&&entry.front()==L'"'&&entry.back()==L'"')entry=entry.substr(1,entry.size()-2);if(!entry.empty())env.pathDirectories.emplace_back(entry);if(end==std::wstring::npos)break;start=end+1;}
    for(auto home:{env.localData/L"pnpm",env.pnpmHome}) {
        if(home.empty())continue;std::error_code ec;auto global=home/L"global";
        if(!std::filesystem::is_directory(global,ec))continue;
        for(auto& version:std::filesystem::directory_iterator(global,ec)) {
            auto modules=version.path()/L"node_modules";env.pnpmModules.push_back(modules);auto store=modules/L".pnpm";
            if(std::filesystem::is_directory(store,ec))for(auto& item:std::filesystem::directory_iterator(store,ec))
                if(item.path().filename().wstring().rfind(L"@openai+codex",0)==0)env.pnpmPackages.push_back(item.path());
        }
    }
    return env;
}
inline std::filesystem::path FindCli() {
    auto env=Locations();
    for(auto& path:CliCandidates(env))if(File(path))return std::filesystem::absolute(path);
    return {};
}
inline std::filesystem::path ConfigPath(const std::filesystem::path& explicitPath) {
    auto path=explicitPath.empty()?Core::Config::FindConfig():std::filesystem::absolute(explicitPath);
    Core::Config validated;
    if(path.empty()||!validated.Load(path))throw std::runtime_error("A valid config.json is required; use --config or run scripts/setup.bat");
    return std::filesystem::absolute(path);
}
inline bool Active(DWORD pid) {
    Handle ready(OpenEventW(SYNCHRONIZE,FALSE,Core::ReadyEventName(pid).c_str()));
    Handle owner(OpenMutexW(SYNCHRONIZE,FALSE,(L"Local\\CodexProxy_Hooks_"+std::to_wstring(pid)).c_str()));
    return ready.value&&owner.value&&WaitForSingleObject(ready,0)==WAIT_OBJECT_0;
}
inline bool HasCore(DWORD pid) {
    Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32,pid));
    MODULEENTRY32W module{};module.dwSize=sizeof(module);
    if(!Module32FirstW(snapshot,&module))return false;
    do{if(_wcsicmp(module.szModule,L"codex_proxy.dll")==0)return true;}while(Module32NextW(snapshot,&module));return false;
}
inline bool Inject(HANDLE process,const std::filesystem::path& dll,const std::filesystem::path& config,bool force,std::string& error) {
    DWORD pid=GetProcessId(process);
    if(!pid||pid==GetCurrentProcessId()){error="Invalid injection target";return false;}
    if(Active(pid))return true;
    auto image=ProcessImage(process);
    if(image.empty()){error="Cannot read target image";return false;}
    Handle mapping(Core::CreateLaunchRequest(pid,config,image,force));
    if(!mapping.value){error="Cannot create launch request (another request may be in progress)";return false;}
    return Injection::ProcessInjector::InjectDll(process,dll.wstring(),&error);
}
struct CaseLess {bool operator()(const std::wstring& a,const std::wstring& b)const{return _wcsicmp(a.c_str(),b.c_str())<0;}};
inline std::vector<wchar_t> ChildEnvironment(const std::filesystem::path& config) {
    std::map<std::wstring,std::wstring,CaseLess> values;
    wchar_t* block=GetEnvironmentStringsW();
    if(!block)throw std::runtime_error("Cannot read environment");
    for(auto p=block;*p;p+=wcslen(p)+1){std::wstring entry=p;auto equals=entry.find(L'=',entry.front()==L'='?1:0);if(equals!=std::wstring::npos)values[entry.substr(0,equals)]=entry.substr(equals+1);}
    FreeEnvironmentStringsW(block); values[L"CODEX_PROXY_CONFIG"]=config.wstring();
    std::vector<wchar_t> out;
    for(auto& pair:values){auto entry=pair.first+L"="+pair.second;out.insert(out.end(),entry.begin(),entry.end());out.push_back(0);}out.push_back(0);return out;
}
inline HANDLE Standard(DWORD id){HANDLE value=GetStdHandle(id);if(value==INVALID_HANDLE_VALUE)return nullptr;if(value)SetHandleInformation(value,HANDLE_FLAG_INHERIT,HANDLE_FLAG_INHERIT);return value;}
inline bool Spawn(const std::filesystem::path& target,const std::vector<std::wstring>& arguments,
    const std::filesystem::path& config,HANDLE job,bool console,bool force,PROCESS_INFORMATION& process,std::string& error,
    const std::filesystem::path& argv0Override={}) {
    auto dll=Core::ModuleDirectory()/L"codex_proxy.dll";
    if(!File(dll)){error="codex_proxy.dll is missing beside launcher";return false;}
    auto command=Command(argv0Override.empty()?target:argv0Override,arguments);auto env=ChildEnvironment(config);
    STARTUPINFOW startup{};startup.cb=sizeof(startup);
    if(console){startup.dwFlags=STARTF_USESTDHANDLES;startup.hStdInput=Standard(STD_INPUT_HANDLE);startup.hStdOutput=Standard(STD_OUTPUT_HANDLE);startup.hStdError=Standard(STD_ERROR_HANDLE);}
    if(!CreateProcessW(target.c_str(),command.data(),nullptr,nullptr,console?TRUE:FALSE,
        CREATE_SUSPENDED|CREATE_UNICODE_ENVIRONMENT,env.data(),nullptr,&startup,&process)){error="CreateProcessW error="+std::to_string(GetLastError());return false;}
    auto fail=[&]{TerminateProcess(process.hProcess,125);WaitForSingleObject(process.hProcess,5000);CloseHandle(process.hThread);CloseHandle(process.hProcess);process={};return false;};
    if(job&&!AssignProcessToJobObject(job,process.hProcess)){error="Cannot assign child to Job, error="+std::to_string(GetLastError());return fail();}
    if(!Inject(process.hProcess,dll,config,force,error))return fail();
    if(ResumeThread(process.hThread)==static_cast<DWORD>(-1)){error="ResumeThread failed";return fail();}
    return true;
}
}
