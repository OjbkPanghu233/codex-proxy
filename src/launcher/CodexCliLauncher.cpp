// Inspired by antigravity-proxy's ACP launcher (BSD-2-Clause); see AUTHORS.txt.
#include "LauncherSupport.hpp"
namespace { BOOL WINAPI Control(DWORD event){return event==CTRL_C_EVENT||event==CTRL_BREAK_EVENT;} }
int wmain(int argc,wchar_t** argv) {
    try {
        auto options=Launcher::ParseCli({argv+1,argv+argc});
        if(options.help){Launcher::Stderr(L"Codex-Proxy 0.2.0\n  codex-proxy [--config path] [codex args...]\n  codex-proxy [--config path] --exec target.exe [args...]\n  codex-proxy [--config path] --attach PID\n  Use -- before Codex arguments that conflict with wrapper flags.");return 0;}
        if(options.version){Launcher::Stderr(L"Codex-Proxy 0.2.0 (Windows x64)");return 0;}
        auto config=Launcher::ConfigPath(options.config);
        if(options.attach){
            Launcher::Handle process(OpenProcess(PROCESS_CREATE_THREAD|PROCESS_QUERY_INFORMATION|PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_VM_READ|SYNCHRONIZE,FALSE,options.attach));
            std::string error;
            if(!process.value||!Launcher::Inject(process,Core::ModuleDirectory()/L"codex_proxy.dll",config,true,error))throw std::runtime_error(error.empty()?"OpenProcess failed":error);
            return 0;
        }
        auto target=options.generic?Launcher::ResolveExecutable(options.target):Launcher::FindCli();
        if(target.empty())throw std::runtime_error("Native codex.exe not found; use CODEX_PROXY_TARGET_EXE or --exec");
        if(Core::SameImage(target,Core::ModulePath()))throw std::runtime_error("Launcher cannot wrap itself");
        Launcher::Handle job(CreateJobObjectW(nullptr,nullptr));
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE|JOB_OBJECT_LIMIT_BREAKAWAY_OK;
        if(!job.value||!SetInformationJobObject(job,JobObjectExtendedLimitInformation,&limits,sizeof(limits)))throw std::runtime_error("Cannot create cleanup Job");
        SetConsoleCtrlHandler(Control,TRUE);
        PROCESS_INFORMATION child{};std::string error;
        if(!Launcher::Spawn(target,options.arguments,config,job,true,options.generic,child,error))throw std::runtime_error(error);
        Launcher::Handle process(child.hProcess),thread(child.hThread);
        if(WaitForSingleObject(process,INFINITE)!=WAIT_OBJECT_0)throw std::runtime_error("Wait for child failed");
        DWORD code=1;if(!GetExitCodeProcess(process,&code))throw std::runtime_error("Cannot read child exit code");
        return static_cast<int>(code);
    }catch(const std::exception& error){Core::Logger::Error(std::string("CLI: ")+error.what());Launcher::Stderr(L"[codex-proxy] "+Launcher::Wide(error.what()));return 125;}
}
