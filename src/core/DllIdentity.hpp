#pragma once
#include "Paths.hpp"
namespace Core {
inline std::string GetDllIdentity() {
    auto path = ModulePath();
    std::error_code ec;
    auto size = std::filesystem::file_size(path, ec);
    auto stamp = std::filesystem::last_write_time(path, ec);
    return path.u8string() + "|" + std::to_string(size) + "|" +
           std::to_string(stamp.time_since_epoch().count());
}
}
