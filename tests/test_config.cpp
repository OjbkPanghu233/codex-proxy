#include "Test.hpp"
int main() {
    Core::Config c; assert(c.proxy.ignore_system_proxy);
    assert(c.desktopHostNetworkHooks);
    assert(c.Parse({{"desktop_host_network_hooks",false}}) && !c.desktopHostNetworkHooks);
    assert(c.Parse({{"desktop_host_network_hooks",true}}) && c.desktopHostNetworkHooks);
    assert(c.ShouldInject("CoDeX.ExE"));
    assert(c.ShouldInject("C:\\app\\ChatGPT.exe"));
    for (auto name : {"powershell.exe","pwsh.exe","cmd.exe","git.exe","node.exe","python.exe","mycodex.exe"}) assert(!c.ShouldInject(name));
    std::string error;
    assert(c.Parse(nlohmann::json::parse(R"({"proxy":{"type":"HTTP","port":8123,"ignore_system_proxy":false},"rules":{"allowed_ports":[443,80,443]},"logging":{"level":"warn"},"traffic_monitor":{"enabled":true},"child_injection":{"enabled":true,"exclude":["chatgpt.exe"]}})"), &error));
    assert(!c.proxy.ignore_system_proxy && c.proxy.port == 8123 && c.proxy.type == "http");
    assert(c.rules.allowed_ports == std::vector<uint16_t>({80,443}));
    assert(c.trafficLogging && !c.ShouldInjectChildProcess("ChatGPT.exe"));
    for (auto invalid : {R"({"proxy":{"port":65536}})",R"({"proxy":{"port":-1}})",R"({"proxy":{"ignore_system_proxy":"true"}})",R"({"rules":{"udp_fallback":"oops"}})",R"({"rules":{"allowed_ports":[65537]}})",R"({"rules":{"allowed_ports":[-1]}})",R"({"fake_ip":{"cidr":"0.0.0.0/0"}})",R"({"child_injection_mode":"inherit"})",R"({"target_processes":["*"]})",R"({"timeout":{"connect":0}})"}) {
        assert(!c.Parse(nlohmann::json::parse(invalid), &error));
        assert(!error.empty() && c.proxy.port == 8123); // no partially mutated config
    }
    assert(c.Parse({{"target_processes", nlohmann::json::array()}}));
    assert(!c.ShouldInject("node.exe") && !c.ShouldInject("codex.exe"));
    assert(c.Parse({{"target_processes", {"node.exe"}}})); assert(c.ShouldInject("node.exe"));
    TestDirectory tmp;
    auto dll = tmp.path / L"dll-\u6d4b\u8bd5";
    auto local = tmp.path / L"local";
    auto overridePath = tmp.path / L"override.json";
    JsonFile(local / L"codex-proxy/config.json", {{"proxy",{{"port",0}}}});
    SetEnvironmentVariableW(L"CODEX_PROXY_CONFIG", nullptr);
    assert(Core::Config::FindConfig(dll, local) == local / L"codex-proxy/config.json");
    JsonFile(dll / L"config.json", {});
    assert(Core::Config::FindConfig(dll, local) == dll / L"config.json");
    auto located = tmp.path / L"custom-\u914d\u7f6e" / L"config.json";
    JsonFile(located, {{"proxy",{{"port",2468}}}});
    auto locator = dll / L"codex-proxy.config-path";
    { std::ofstream file(locator,std::ios::binary); file << "\xef\xbb\xbf" << located.u8string() << "\r\n"; }
    assert(Core::Config::FindConfig(dll, local) == dll / L"config.json");
    std::filesystem::remove(dll / L"config.json");
    assert(Core::Config::FindConfig(dll, local) == located);
    { std::ofstream file(locator); file << (tmp.path/L"missing.json").u8string(); }
    assert(Core::Config::FindConfig(dll, local) == local / L"codex-proxy/config.json");
    { std::ofstream file(locator); file << "relative/config.json\n"; }
    assert(Core::Config::FindConfig(dll, local) == local / L"codex-proxy/config.json");
    { std::ofstream file(locator); file << located.u8string(); }
    JsonFile(dll / L"config.json", {});
    SetEnvironmentVariableW(L"CODEX_PROXY_CONFIG", overridePath.c_str());
    assert(Core::Config::FindConfig(dll, local) == dll / L"config.json");
    JsonFile(overridePath, {{"proxy",{{"port",0}}}});
    assert(Core::Config::FindConfig(dll, local) == overridePath);
    std::filesystem::remove(dll / L"config.json");
    assert(Core::Config::FindConfig(dll, local) == overridePath); // env outranks locator
    assert(c.Load()); assert(c.proxy.port == 0 && c.proxy.ignore_system_proxy);
    JsonFile(overridePath, {{"proxy",{{"port","secret-must-not-be-logged"}}}});
    assert(!c.Load()); // present but invalid override never silently falls back
    SetEnvironmentVariableW(L"CODEX_PROXY_CONFIG", nullptr);
}
