#pragma once
#include "CliLauncherLogic.hpp"
#include <algorithm>
#include <cwctype>
namespace Launcher {
struct DesktopOptions {
    std::filesystem::path target,config;
    bool restart=false,attach=false,dryRun=false,syncLocal=false;
    std::vector<std::wstring> arguments;
};
inline DesktopOptions ParseDesktop(const std::vector<std::wstring>& args) {
    DesktopOptions options;
    for(size_t i=0;i<args.size();++i) {
        auto value=[&]() { if(++i==args.size()||args[i].empty()) throw std::invalid_argument("Missing option value"); return args[i]; };
        if(args[i]==L"--target") options.target=value();
        else if(args[i]==L"--config") options.config=value();
        else if(args[i]==L"--restart") options.restart=true;
        else if(args[i]==L"--attach") options.attach=true;
        else if(args[i]==L"--dry-run") options.dryRun=true;
        else if(args[i]==L"--sync-local") options.syncLocal=true;
        else { auto start=args[i]==L"--"?i+1:i; options.arguments.assign(args.begin()+start,args.end()); break; }
    }
    if(options.restart&&options.attach) throw std::invalid_argument("Choose --restart or --attach");
    return options;
}
inline std::wstring Lower(std::wstring s) { for(auto& c:s)c=static_cast<wchar_t>(towlower(c)); return s; }
inline bool IsWindowsApps(const std::filesystem::path& path) {
    auto name=Lower(path.wstring()); std::replace(name.begin(),name.end(),L'/',L'\\');
    return name.find(L"\\windowsapps\\")!=std::wstring::npos;
}
inline std::vector<std::filesystem::path> DesktopCandidates(const DesktopOptions& options,
    const std::filesystem::path& saved,const std::filesystem::path& local,
    const std::vector<std::filesystem::path>& packages) {
    std::vector<std::filesystem::path> out;
    if(!options.target.empty()) return {options.target};
    if(!saved.empty()) out.push_back(saved);
    if(!local.empty()) out.push_back(local/L"Microsoft/WindowsApps/chatgpt-desktop.exe");
    out.insert(out.end(),packages.begin(),packages.end());
    if(!local.empty()) { out.push_back(local/L"Programs/Codex/Codex.exe"); out.push_back(local/L"Programs/Codex/ChatGPT.exe"); }
    return out;
}
enum class DesktopAction { Launch, Wake, Restart, Attach, Ask, DryRun, MissingRunning };
inline DesktopAction ChooseDesktopAction(bool running,bool protectedProcess,const DesktopOptions& options) {
    if(options.dryRun) return DesktopAction::DryRun;
    if(!running) return options.attach?DesktopAction::MissingRunning:DesktopAction::Launch;
    if(options.restart) return DesktopAction::Restart;
    if(options.attach) return DesktopAction::Attach;
    return protectedProcess?DesktopAction::Wake:DesktopAction::Ask;
}
inline bool ShouldCopy(const std::filesystem::path& source,const std::filesystem::path& target,
    bool targetExists,bool sameBytes) {
    if(source==target) return false;
    if(Lower(target.filename().wstring())==L"config.json" && targetExists) return false;
    return !targetExists||!sameBytes;
}
}
