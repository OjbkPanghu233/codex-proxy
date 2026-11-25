#include "Test.hpp"
#include "hooks/ProcessName.hpp"
int main() {
    using namespace Hooks;
    assert(GetCreateProcessTargetBaseNameA(nullptr, "\"C:\\Program Files\\App\\ChatGPT.exe\" --x") == "ChatGPT.exe");
    assert(GetCreateProcessTargetBaseNameA("C:\\app\\codex.exe", "cmd.exe") == "codex.exe");
    assert(ClassifyProcess("ChatGPT.exe", "app.exe") == ProcessRole::DesktopMain);
    assert(ClassifyProcess("CHATGPT.EXE", "app.exe --type=utility --utility-sub-type=network.mojom.NetworkService") == ProcessRole::NetworkService);
    assert(ClassifyProcess("ChatGPT.exe", "app.exe --type utility --utility-sub-type \"network.mojom.NetworkService\"") == ProcessRole::NetworkService);
    for (auto type : {"renderer","gpu-process","crashpad-handler","utility","zygote"}) {
        auto role = ClassifyProcess("ChatGPT.exe", std::string("app.exe --type=")+type);
        assert(role == ProcessRole::ChromiumOther && !IsInjectableRole(role) && !EnableNetworkHooks(role));
    }
    assert(ClassifyProcess("ChatGPT.exe", "app.exe --note=--type=renderer") == ProcessRole::DesktopMain);
    assert(ClassifyProcess("ChatGPT.exe", "app.exe --type=utility --utility-sub-type=network.mojom.NetworkServiceFake") == ProcessRole::ChromiumOther);
    for (auto name : {"codex.exe","codex-code-mode-host.exe","codex-computer-use-swift.exe","extension-host.exe"}) assert(EnableNetworkHooks(ClassifyProcess(name,"app.exe")));
    assert(EnableNetworkHooks(ProcessRole::DesktopMain));
    assert(!EnableNetworkHooks(ProcessRole::DesktopMain,false));
    assert(ClassifyProcess("Codex.exe","Codex.exe",true)==ProcessRole::DesktopMain);
    assert(ClassifyProcess("Codex.exe","Codex.exe --type=renderer")==ProcessRole::ChromiumOther);
    assert(EnableNetworkHooks(ProcessRole::NetworkService,false));
    assert(ClassifyProcess("node.exe", "node.exe codex.exe") == ProcessRole::NotTarget);
}
