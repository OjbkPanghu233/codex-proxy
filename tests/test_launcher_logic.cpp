#include "Test.hpp"
#include "launcher/CliLauncherLogic.hpp"
#include "launcher/DesktopLauncherLogic.hpp"
#include <shellapi.h>
#pragma comment(lib,"shell32.lib")
int main() {
    using namespace Launcher;
    std::vector<std::wstring> arguments={L"",L"space argument",L"quote\"inside",L"C:\\trailing slash\\",L"unicode-\u4ee3\u7406",L"\\\"",L"--json"};
    auto command=Command(L"C:\\program files\\target.exe",arguments);int count=0;
    auto argv=CommandLineToArgvW(command.c_str(),&count);assert(argv&&count==arguments.size()+1);
    for(int i=1;i<count;++i)assert(argv[i]==arguments[i-1]);LocalFree(argv);
    auto options=ParseCli({L"--config",L"config with spaces.json",L"--exec",L"custom.exe",L"exec",L"--json"});
    assert(options.generic&&options.target==L"custom.exe"&&options.arguments==std::vector<std::wstring>({L"exec",L"--json"}));
    assert(ParseCli({L"--attach",L"123"}).attach==123);
    assert(ParseCli({L"--",L"--config",L"codex-value"}).arguments.front()==L"--config");
    for(auto args:{std::vector<std::wstring>{L"--exec"},std::vector<std::wstring>{L"--attach",L"0"},std::vector<std::wstring>{L"--attach",L"4294967296"},std::vector<std::wstring>{L"--attach",L"12x"}}){bool rejected=false;try{ParseCli(args);}catch(...){rejected=true;}assert(rejected);}
    CliLocations env;env.appData=L"C:/roaming";env.localData=L"C:/local";env.profile=L"C:/user";env.pathDirectories={L"C:/path"};
    auto candidates=CliCandidates(env);assert(candidates.front().wstring().find(L"codex/node_modules")!=std::wstring::npos);
    assert(candidates.back()==env.localData/L"codex/codex.exe");
    env.overrideExe=L"D:/custom/codex.exe";assert(CliCandidates(env)==std::vector<std::filesystem::path>({env.overrideExe}));
    auto desktop=ParseDesktop({L"--config",L"config.json",L"--target",L"app.exe",L"--dry-run"});assert(desktop.dryRun&&desktop.target==L"app.exe");
    assert(DesktopCandidates(desktop,L"saved.exe",L"local",{})==std::vector<std::filesystem::path>({L"app.exe"}));
    DesktopOptions basic;auto paths=DesktopCandidates(basic,L"saved.exe",L"local",{L"package/app/ChatGPT.exe"});assert(paths[0]==L"saved.exe"&&paths[1]==L"local/Microsoft/WindowsApps/chatgpt-desktop.exe");
    assert(ChooseDesktopAction(true,false,basic)==DesktopAction::Ask);
    assert(ChooseDesktopAction(true,true,basic)==DesktopAction::Wake);
    basic.restart=true;assert(ChooseDesktopAction(true,true,basic)==DesktopAction::Restart);
    basic.dryRun=true;assert(ChooseDesktopAction(true,false,basic)==DesktopAction::DryRun);
    assert(IsWindowsApps(L"C:\\Program Files\\WindowsApps\\OpenAI.Codex_1\\app\\ChatGPT.exe"));
    assert(!IsWindowsApps(L"C:\\Apps\\WindowsApps-copy\\ChatGPT.exe"));
    assert(!ShouldCopy(L"source",L"config.json",true,false));assert(ShouldCopy(L"source",L"version.dll",true,false));
}
