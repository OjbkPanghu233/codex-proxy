// Derived from antigravity-proxy (BSD-2-Clause); see LICENSE.txt / AUTHORS.txt.
#pragma once

#include <algorithm>
#include <cctype>
#include <string>
#include <utility>
#include <vector>

namespace Hooks {

inline std::string ToLowerAsciiCopy(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

inline void TrimAsciiInPlace(std::string& s) {
    auto isWs = [](unsigned char c) { return std::isspace(c) != 0; };
    size_t begin = 0;
    while (begin < s.size() && isWs(static_cast<unsigned char>(s[begin]))) begin++;
    size_t end = s.size();
    while (end > begin && isWs(static_cast<unsigned char>(s[end - 1]))) end--;
    s = s.substr(begin, end - begin);
}

inline std::string StripOuterQuotesCopy(std::string s) {
    TrimAsciiInPlace(s);
    if (s.size() >= 2 && s.front() == '"' && s.back() == '"') {
        s = s.substr(1, s.size() - 2);
        TrimAsciiInPlace(s);
    }
    return s;
}

inline std::string ExtractBaseNameFromPathLike(std::string s) {
    s = StripOuterQuotesCopy(std::move(s));
    const size_t lastSlash = s.find_last_of("\\/");
    if (lastSlash != std::string::npos) {
        s = s.substr(lastSlash + 1);
    }
    return StripOuterQuotesCopy(std::move(s));
}

inline std::string ExtractExecutableTokenFromCommandLine(std::string commandLine) {
    commandLine = StripOuterQuotesCopy(std::move(commandLine));
    if (commandLine.empty()) return "";

    // CreateProcess 的命令行可能是 `"C:\...\Antigravity IDE.exe" --flag`。
    // 先保留引号内完整路径，避免把带空格的 exe 名截断成 `Antigravity`。
    if (commandLine.front() == '"') {
        const size_t closingQuote = commandLine.find('"', 1);
        if (closingQuote != std::string::npos) {
            return commandLine.substr(1, closingQuote - 1);
        }
    }

    const std::string lowerCommandLine = ToLowerAsciiCopy(commandLine);
    const size_t exePos = lowerCommandLine.find(".exe");
    if (exePos != std::string::npos) {
        return commandLine.substr(0, exePos + 4);
    }

    const size_t firstSpace = commandLine.find(' ');
    if (firstSpace != std::string::npos) {
        return commandLine.substr(0, firstSpace);
    }
    return commandLine;
}

inline std::string GetCreateProcessTargetBaseNameA(const char* applicationName, const char* commandLine) {
    std::string target;
    if (applicationName && *applicationName) {
        target = applicationName;
    } else if (commandLine && *commandLine) {
        target = ExtractExecutableTokenFromCommandLine(commandLine);
    }
    target = ExtractBaseNameFromPathLike(std::move(target));
    return target.empty() ? std::string("Unknown") : target;
}


enum class ProcessRole { NotTarget, DesktopMain, NetworkService, ChromiumOther, Engine };
inline bool IsCodexHostProcessName(const std::string& name) {
    return ToLowerAsciiCopy(ExtractBaseNameFromPathLike(name)) == "chatgpt.exe";
}
inline bool IsCodexEngineProcessName(const std::string& name) {
    auto n = ToLowerAsciiCopy(ExtractBaseNameFromPathLike(name));
    return n == "codex.exe" || n == "codex-code-mode-host.exe" ||
           n == "codex-computer-use-swift.exe" || n == "extension-host.exe";
}
// Windows argument quoting, sufficient for role flags without substring matches.
inline std::vector<std::string> SplitCommandLine(const std::string& text) {
    std::vector<std::string> args;
    size_t i = 0;
    while (i < text.size()) {
        while (i < text.size() && std::isspace(static_cast<unsigned char>(text[i]))) ++i;
        if (i == text.size()) break;
        std::string arg;
        bool quoted = false;
        while (i < text.size()) {
            if (!quoted && std::isspace(static_cast<unsigned char>(text[i]))) break;
            size_t slashes = 0;
            while (i < text.size() && text[i] == '\\') { ++slashes; ++i; }
            if (i < text.size() && text[i] == '"') {
                arg.append(slashes / 2, '\\');
                if (slashes % 2) arg += '"'; else quoted = !quoted;
                ++i;
            } else {
                arg.append(slashes, '\\');
                if (i < text.size()) arg += text[i++];
            }
        }
        args.push_back(std::move(arg));
    }
    return args;
}
inline std::string SwitchValue(const std::vector<std::string>& args, const std::string& flag) {
    std::string value;
    for (size_t i = 1; i < args.size(); ++i) {
        if (args[i].compare(0, flag.size() + 1, flag + "=") == 0) value = args[i].substr(flag.size()+1);
        else if (args[i] == flag && i + 1 < args.size()) value = args[++i];
    }
    return value;
}
inline ProcessRole ClassifyProcess(const std::string& name, const std::string& commandLine, bool desktopHostHint=false) {
    auto args = SplitCommandLine(commandLine);
    auto type = SwitchValue(args, "--type");
    bool codexDesktop=ToLowerAsciiCopy(ExtractBaseNameFromPathLike(name))=="codex.exe" && (desktopHostHint||!type.empty());
    if (IsCodexEngineProcessName(name) && !codexDesktop) return ProcessRole::Engine;
    if (!IsCodexHostProcessName(name) && !codexDesktop) return ProcessRole::NotTarget;
    if (type.empty()) return ProcessRole::DesktopMain;
    if (type == "utility" && SwitchValue(args, "--utility-sub-type") == "network.mojom.NetworkService")
        return ProcessRole::NetworkService;
    return ProcessRole::ChromiumOther;
}
inline bool EnableNetworkHooks(ProcessRole role, bool desktopHostNetworkHooks = true) {
    return role == ProcessRole::Engine || role == ProcessRole::NetworkService ||
           (role == ProcessRole::DesktopMain && desktopHostNetworkHooks);
}
inline bool IsInjectableRole(ProcessRole role) { return role != ProcessRole::ChromiumOther; }
} // namespace Hooks
