#pragma once
#include <filesystem>
#include <string>
#include <vector>
#include <stdexcept>
#include <cstdint>
namespace Launcher {
inline std::wstring Quote(const std::wstring& value) {
    if(!value.empty() && value.find_first_of(L" \t\n\v\"")==std::wstring::npos) return value;
    std::wstring out=L"\""; size_t slashes=0;
    for(auto ch:value) {
        if(ch==L'\\') { ++slashes; continue; }
        if(ch==L'\"') { out.append(slashes*2+1,L'\\'); out+=ch; }
        else { out.append(slashes,L'\\'); out+=ch; }
        slashes=0;
    }
    out.append(slashes*2,L'\\'); return out+L"\"";
}
inline std::wstring Command(const std::filesystem::path& exe,const std::vector<std::wstring>& args) {
    auto command=Quote(exe.wstring()); for(auto& arg:args) command+=L" "+Quote(arg); return command;
}
struct CliOptions {
    std::filesystem::path target,config;
    uint32_t attach=0;
    bool generic=false,help=false,version=false;
    std::vector<std::wstring> arguments;
};
inline CliOptions ParseCli(const std::vector<std::wstring>& args) {
    CliOptions options;
    for(size_t i=0;i<args.size();++i) {
        auto value=[&]() -> std::wstring { if(++i==args.size() || args[i].empty()) throw std::invalid_argument("Missing option value"); return args[i]; };
        if(args[i]==L"--config") options.config=value();
        else if(args[i]==L"--exec") { options.target=value(); options.generic=true; options.arguments.assign(args.begin()+i+1,args.end()); break; }
        else if(args[i]==L"--attach") {
            auto text=value(); uint64_t pid=0;
            for(auto c:text) { if(c<L'0'||c>L'9'||pid>429496729) throw std::invalid_argument("Invalid PID"); pid=pid*10+c-L'0'; }
            if(!pid||pid>UINT32_MAX) throw std::invalid_argument("Invalid PID"); options.attach=static_cast<uint32_t>(pid);
        } else if(args[i]==L"--help" && i==0) options.help=true;
        else if(args[i]==L"--version" && i==0) options.version=true;
        else { size_t start=args[i]==L"--"?i+1:i; options.arguments.assign(args.begin()+start,args.end()); break; }
    }
    if(options.attach && (options.generic||!options.arguments.empty())) throw std::invalid_argument("--attach cannot launch another target");
    return options;
}
struct CliLocations {
    std::filesystem::path overrideExe,appData,localData,profile,bunInstall,pnpmHome;
    std::vector<std::filesystem::path> pathDirectories,pnpmPackages,pnpmModules;
};
inline void NpmCandidates(std::vector<std::filesystem::path>& out,const std::filesystem::path& modules) {
    auto native=std::filesystem::path(L"vendor/x86_64-pc-windows-msvc/bin/codex.exe");
    out.push_back(modules/L"@openai/codex/node_modules/@openai/codex-win32-x64"/native);
    out.push_back(modules/L"@openai/codex"/native);
    out.push_back(modules/L"@openai/codex-win32-x64"/native);
}
inline std::vector<std::filesystem::path> CliCandidates(const CliLocations& env) {
    if(!env.overrideExe.empty()) return {env.overrideExe};
    std::vector<std::filesystem::path> out;
    if(!env.appData.empty()) NpmCandidates(out,env.appData/L"npm/node_modules");
    if(!env.localData.empty()) NpmCandidates(out,env.localData/L"pnpm/global/5/node_modules");
    if(!env.pnpmHome.empty()) NpmCandidates(out,env.pnpmHome/L"global/5/node_modules");
    for(auto& modules:env.pnpmModules) NpmCandidates(out,modules);
    for(auto& package:env.pnpmPackages) NpmCandidates(out,package/L"node_modules");
    if(!env.bunInstall.empty()) NpmCandidates(out,env.bunInstall/L"install/global/node_modules");
    if(!env.profile.empty()) NpmCandidates(out,env.profile/L".bun/install/global/node_modules");
    for(auto& folder:env.pathDirectories) if(!folder.empty()) out.push_back(folder/L"codex.exe");
    if(!env.localData.empty()) out.push_back(env.localData/L"codex/codex.exe");
    return out;
}
}
