#include "LauncherSupport.hpp"
#include "DesktopLauncherLogic.hpp"
#include <commdlg.h>
#include <cstring>
namespace {
struct Process { DWORD pid=0,parent=0;std::filesystem::path image;std::wstring command; };
std::wstring CommandLine(HANDLE process) {
    using Query=LONG(NTAPI*)(HANDLE,ULONG,PVOID,ULONG,PULONG);
    auto query=reinterpret_cast<Query>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQueryInformationProcess"));
    if(!query)return {};
    ULONG count=0;query(process,60,nullptr,0,&count);
    if(!count||count>1024*1024)return {};
    std::vector<unsigned char> buffer(count);
    if(query(process,60,buffer.data(),count,&count)<0)return {};
    struct UnicodeString { USHORT length,maximum;PWSTR data; };
    auto text=reinterpret_cast<UnicodeString*>(buffer.data());
    auto begin=reinterpret_cast<uintptr_t>(buffer.data()),end=begin+buffer.size(),pointer=reinterpret_cast<uintptr_t>(text->data);
    if(pointer<begin||pointer>end||text->length>end-pointer)return {};
    return std::wstring(text->data,text->length/sizeof(wchar_t));
}
std::vector<Process> Processes() {
    Launcher::Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0));
    PROCESSENTRY32W entry{};entry.dwSize=sizeof(entry);std::vector<Process> result;
    if(!Process32FirstW(snapshot,&entry))return result;
    DWORD session=0;ProcessIdToSessionId(GetCurrentProcessId(),&session);
    do {
        DWORD other=~0u;if(!ProcessIdToSessionId(entry.th32ProcessID,&other)||other!=session)continue;
        Process value;value.pid=entry.th32ProcessID;value.parent=entry.th32ParentProcessID;
        Launcher::Handle process(OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,value.pid));
        if(process.value){value.image=Launcher::ProcessImage(process);auto name=value.image.filename().u8string();if(Hooks::IsCodexHostProcessName(name)||Hooks::IsCodexEngineProcessName(name))value.command=CommandLine(process);}
        else {Launcher::Handle limited(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,value.pid));if(limited.value)value.image=Launcher::ProcessImage(limited);}
        if(!value.image.empty())result.push_back(std::move(value));
    }while(Process32NextW(snapshot,&entry));
    return result;
}
std::filesystem::path SavedTarget() {
    for(auto path:{Core::ModuleDirectory()/L"desktop_path.txt",std::filesystem::path(Core::Environment(L"LOCALAPPDATA"))/L"codex-proxy/desktop_path.txt"}) {
        std::ifstream file(path,std::ios::binary);std::string line;if(!std::getline(file,line))continue;
        if(line.rfind("\xef\xbb\xbf",0)==0)line.erase(0,3);
        auto value=Launcher::Wide(line);auto end=value.find_last_not_of(L" \r\n\t\"");auto start=value.find_first_not_of(L" \r\n\t\"");
        if(start!=std::wstring::npos)return value.substr(start,end-start+1);
    }
    return {};
}
std::filesystem::path PickTarget() {
    wchar_t path[32768]{};OPENFILENAMEW dialog{};dialog.lStructSize=sizeof(dialog);
    dialog.lpstrFile=path;dialog.nMaxFile=32768;dialog.lpstrFilter=L"Codex / ChatGPT (*.exe)\0*.exe\0\0";
    dialog.lpstrTitle=L"选择 Codex / ChatGPT 主程序 · Select desktop executable";
    dialog.Flags=OFN_FILEMUSTEXIST|OFN_PATHMUSTEXIST|OFN_NOCHANGEDIR;
    if(!GetOpenFileNameW(&dialog))return {};
    auto record=Core::ModuleDirectory()/L"desktop_path.txt";std::ofstream file(record,std::ios::binary);
    if(!file){record=std::filesystem::path(Core::Environment(L"LOCALAPPDATA"))/L"codex-proxy/desktop_path.txt";std::error_code ec;std::filesystem::create_directories(record.parent_path(),ec);file.open(record,std::ios::binary);}
    if(file)file<<Launcher::Utf8(path)<<"\n";return path;
}
bool SameBytes(const std::filesystem::path& a,const std::filesystem::path& b) {
    std::error_code ec;if(!Launcher::File(b)||std::filesystem::file_size(a,ec)!=std::filesystem::file_size(b,ec)||ec)return false;
    std::ifstream left(a,std::ios::binary),right(b,std::ios::binary);char x[16384],y[16384];
    do{left.read(x,sizeof(x));right.read(y,sizeof(y));if(left.gcount()!=right.gcount()||memcmp(x,y,static_cast<size_t>(left.gcount())))return false;}while(left.gcount());return true;
}
void SyncWritable(const std::filesystem::path& target,const std::filesystem::path& config) {
    auto folder=target.parent_path();if(Launcher::IsWindowsApps(target)||Core::SameImage(folder,Core::ModuleDirectory()))return;
    auto probe=folder/(L".codex-proxy-write-"+std::to_wstring(GetCurrentProcessId()));
    Launcher::Handle writable(CreateFileW(probe.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_TEMPORARY|FILE_FLAG_DELETE_ON_CLOSE,nullptr));
    if(writable.value==INVALID_HANDLE_VALUE)return;
    for(auto name:{L"version.dll",L"codex_proxy.dll",L"config.json"}) {
        auto source=std::wstring(name)==L"config.json"?config:Core::ModuleDirectory()/name;
        auto destination=folder/name;
        if(!Launcher::File(source)||!Launcher::ShouldCopy(source,destination,Launcher::File(destination),SameBytes(source,destination)))continue;
        if(Launcher::File(destination)&&std::wstring(name)!=L"config.json") {
            auto backup=folder/L".codex-proxy-original"/name;std::error_code ec;std::filesystem::create_directories(backup.parent_path(),ec);
            if(!Launcher::File(backup)&&!CopyFileW(destination.c_str(),backup.c_str(),TRUE))throw std::runtime_error("Cannot back up existing desktop DLL");
        }
        if(!CopyFileW(source.c_str(),destination.c_str(),FALSE))throw std::runtime_error("Cannot synchronize desktop DLL/config; close the app and retry");
    }
}
bool MatchesDesktopImage(const Process& process,const std::vector<std::filesystem::path>& candidates,bool packageScope) {
    for(auto& target:candidates)if(Launcher::File(target)&&Core::SameImage(target,process.image))return true;
    auto name=Launcher::Lower(process.image.filename().wstring());auto path=Launcher::Lower(process.image.wstring());
    return packageScope&&(name==L"chatgpt.exe"||name==L"codex.exe")&&path.find(L"\\windowsapps\\openai.codex_")!=std::wstring::npos&&process.image.parent_path().filename()==L"app";
}
bool IsPackageScope(const std::vector<std::filesystem::path>& candidates) {
    return std::any_of(candidates.begin(),candidates.end(),[](const std::filesystem::path& p){auto path=Launcher::Lower(p.wstring());return Launcher::Lower(p.filename().wstring())==L"chatgpt-desktop.exe"||path.find(L"\\windowsapps\\openai.codex_")!=std::wstring::npos;});
}
std::vector<Process> Roots(const std::vector<Process>& all,const std::vector<std::filesystem::path>& candidates) {
    std::vector<Process> matches,result;
    bool packageScope=IsPackageScope(candidates);
    for(auto& process:all) {
        if(!MatchesDesktopImage(process,candidates,packageScope))continue;
        auto role=Hooks::ClassifyProcess(process.image.filename().u8string(),Launcher::Utf8(process.command));
        if(role==Hooks::ProcessRole::NetworkService||role==Hooks::ProcessRole::ChromiumOther)continue;
        matches.push_back(process);
    }
    for(auto& process:matches) {
        if(std::none_of(matches.begin(),matches.end(),[&](const Process& parent){return parent.pid==process.parent;}))result.push_back(process);
    }
    return result;
}
void CleanupOrphanChildren(const std::vector<Process>& all,const std::vector<std::filesystem::path>& candidates) {
    bool packageScope=IsPackageScope(candidates);
    std::set<DWORD> alive;for(auto& p:all)alive.insert(p.pid);
    for(auto& process:all) {
        if(!MatchesDesktopImage(process,candidates,packageScope))continue;
        auto role=Hooks::ClassifyProcess(process.image.filename().u8string(),Launcher::Utf8(process.command));
        if(role!=Hooks::ProcessRole::NetworkService&&role!=Hooks::ProcessRole::ChromiumOther)continue;
        if(alive.count(process.parent))continue;
        Launcher::Handle handle(OpenProcess(SYNCHRONIZE|PROCESS_TERMINATE,FALSE,process.pid));
        if(handle.value){TerminateProcess(handle,0);WaitForSingleObject(handle,3000);}
    }
}
std::vector<Process> Tree(const std::vector<Process>& all,const std::vector<Process>& roots) {
    std::set<DWORD> ids;for(auto& p:roots)ids.insert(p.pid);
    bool changed=true;while(changed){changed=false;for(auto& p:all)if(ids.count(p.parent)&&ids.insert(p.pid).second)changed=true;}
    std::vector<Process> result;for(auto& p:all)if(ids.count(p.pid))result.push_back(p);return result;
}
void Attach(const std::vector<Process>& all,const std::vector<Process>& roots,const std::filesystem::path& config) {
    Core::Config settings;if(!settings.Load(config))throw std::runtime_error("Invalid configuration");
    for(auto& p:Tree(all,roots)) {
        auto name=p.image.filename().u8string();bool root=std::any_of(roots.begin(),roots.end(),[&](const Process& item){return item.pid==p.pid;});
        if(!root&&(!settings.ShouldInject(name)||(Hooks::IsCodexHostProcessName(name)&&p.command.empty())))continue;
        if(!Hooks::IsInjectableRole(Hooks::ClassifyProcess(name,Launcher::Utf8(p.command))))continue;
        Launcher::Handle process(OpenProcess(PROCESS_CREATE_THREAD|PROCESS_QUERY_INFORMATION|PROCESS_VM_READ|PROCESS_VM_WRITE|PROCESS_VM_OPERATION|SYNCHRONIZE,FALSE,p.pid));
        std::string error;if(!process.value||!Launcher::Inject(process,Core::ModuleDirectory()/L"codex_proxy.dll",config,root,error))throw std::runtime_error("Attach PID "+std::to_string(p.pid)+" failed: "+error+"; restart the desktop to apply proxy");
    }
}
BOOL CALLBACK WakeWindow(HWND window,LPARAM pid) {
    DWORD owner=0;GetWindowThreadProcessId(window,&owner);
    if(owner==static_cast<DWORD>(pid)&&IsWindowVisible(window)){ShowWindow(window,SW_RESTORE);SetForegroundWindow(window);}return TRUE;
}
BOOL CALLBACK CloseWindow(HWND window,LPARAM pid) {DWORD owner=0;GetWindowThreadProcessId(window,&owner);if(owner==static_cast<DWORD>(pid))PostMessageW(window,WM_CLOSE,0,0);return TRUE;}
void Restart(const std::vector<Process>& all,const std::vector<Process>& roots) {
    for(auto& p:roots)EnumWindows(CloseWindow,static_cast<LPARAM>(p.pid));
    for(auto& p:Tree(all,roots)) {
        auto name=p.image.filename().u8string();
        if(!Hooks::IsCodexHostProcessName(name)&&!Hooks::IsCodexEngineProcessName(name))continue;
        Launcher::Handle process(OpenProcess(SYNCHRONIZE|PROCESS_TERMINATE,FALSE,p.pid));if(!process.value)continue;
        if(WaitForSingleObject(process,3000)==WAIT_TIMEOUT){if(!TerminateProcess(process,0))throw std::runtime_error("Cannot stop desktop process");WaitForSingleObject(process,5000);}
    }
}
}
int WINAPI wWinMain(HINSTANCE,HINSTANCE,PWSTR,int) {
    bool dry=false;
    try {
        int argc=0;auto argv=CommandLineToArgvW(GetCommandLineW(),&argc);if(!argv)throw std::runtime_error("Cannot parse arguments");
        std::vector<std::wstring> args(argv+1,argv+argc);LocalFree(argv);
        dry=std::find(args.begin(),args.end(),L"--dry-run")!=args.end();
        auto options=Launcher::ParseDesktop(args);dry=options.dryRun;
        auto packages=Launcher::Packages();auto candidates=Launcher::DesktopCandidates(options,SavedTarget(),Core::Environment(L"LOCALAPPDATA"),packages);
        auto all=Processes();std::filesystem::path target;
        for(auto& candidate:candidates)if(Launcher::File(candidate)){target=std::filesystem::absolute(candidate);break;}
        auto roots=Roots(all,target.empty()?candidates:std::vector<std::filesystem::path>{target});
        if(dry) {
            for(auto& candidate:candidates){auto text=L"desktop candidate="+candidate.wstring()+(Launcher::File(candidate)?L" exists":L" missing");Core::Logger::Info(Launcher::Utf8(text));Launcher::Stderr(text);}
            for(auto& p:roots){auto text=L"desktop pid="+std::to_wstring(p.pid)+L" image="+p.image.wstring()+L" module="+(Launcher::HasCore(p.pid)?L"loaded":L"absent")+L" ready="+(Launcher::Active(p.pid)?L"yes":L"no");Core::Logger::Info(Launcher::Utf8(text));Launcher::Stderr(text);}
            Core::Logger::Info("Desktop dry-run complete; no process/config changes");return 0;
        }
        if(target.empty()){if(!options.target.empty())throw std::runtime_error("Explicit desktop executable does not exist");target=PickTarget();if(target.empty())return 0;}
        auto config=Launcher::ConfigPath(options.config);
        bool protectedProcess=!roots.empty()&&std::all_of(roots.begin(),roots.end(),[](const Process& p){return Launcher::HasCore(p.pid)&&Launcher::Active(p.pid);});
        auto action=Launcher::ChooseDesktopAction(!roots.empty(),protectedProcess,options);
        if(action==Launcher::DesktopAction::Ask) {
            int choice=MessageBoxW(nullptr,L"Codex 正在直连运行，尚未启用代理。\nCodex is running without the proxy.\n\n是 / Yes：关闭并以代理模式重启（未保存的操作可能丢失）\n否 / No：热注入当前主进程与网络/引擎子进程\n旧连接不会迁移 / Existing connections are not migrated.\n取消 / Cancel：退出，不做更改",L"Codex-Proxy",MB_YESNOCANCEL|MB_ICONQUESTION|MB_SETFOREGROUND);
            if(choice==IDCANCEL)return 0;action=choice==IDYES?Launcher::DesktopAction::Restart:Launcher::DesktopAction::Attach;
        }
        if(action==Launcher::DesktopAction::MissingRunning)throw std::runtime_error("No running Codex desktop to attach");
        if(action==Launcher::DesktopAction::Attach)Attach(all,roots,config);
        if(action==Launcher::DesktopAction::Restart)Restart(all,roots);
        if(roots.empty()&&action==Launcher::DesktopAction::Launch)CleanupOrphanChildren(all,target.empty()?candidates:std::vector<std::filesystem::path>{target});
        if(action==Launcher::DesktopAction::Wake||action==Launcher::DesktopAction::Attach) {
            for(auto& p:roots)EnumWindows(WakeWindow,static_cast<LPARAM>(p.pid));
            if(options.arguments.empty())return 0;
        }
        if(options.syncLocal && action!=Launcher::DesktopAction::Wake&&action!=Launcher::DesktopAction::Attach)SyncWritable(target,config);
        PROCESS_INFORMATION process{};std::string error;
        std::filesystem::path argv0Override;
        if(Launcher::Lower(target.filename().wstring())==L"chatgpt-desktop.exe")
            for(auto& pkgExe:packages)if(Launcher::File(pkgExe)&&Launcher::Lower(pkgExe.filename().wstring())==L"chatgpt.exe"){argv0Override=pkgExe;break;}
        if(!Launcher::Spawn(target,options.arguments,config,nullptr,false,true,process,error,argv0Override)) {
            bool started=false;
            if(Launcher::Lower(target.filename().wstring())==L"chatgpt-desktop.exe")
                for(auto& fallback:packages)if(Launcher::File(fallback)&&!Core::SameImage(fallback,target))if(Launcher::Spawn(fallback,options.arguments,config,nullptr,false,true,process,error)){started=true;break;}
            if(!started)throw std::runtime_error("Desktop launch failed: "+error);
        }
        CloseHandle(process.hThread);CloseHandle(process.hProcess);return 0;
    }catch(const std::exception& error){Core::Logger::Error(std::string("Desktop: ")+error.what());Launcher::Stderr(Launcher::Wide(error.what()));if(!dry)MessageBoxW(nullptr,(L"Codex 代理启动失败 / Proxy launch failed\n\n"+Launcher::Wide(error.what())).c_str(),L"Codex-Proxy",MB_OK|MB_ICONERROR);return 125;}
}
