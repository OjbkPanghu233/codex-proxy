#pragma once
namespace Hooks {
// Transactional install: any missing API rolls back the entire set.
bool Install(bool enableNetworkHooks);
}
