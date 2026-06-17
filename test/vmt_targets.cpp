#include "vmt_targets.hpp"

// Keep target construction in a separate translation unit so optimized builds
// cannot devirtualize the VMT hook tests and bypass the replaced vtable.

namespace safetyhook::test {
std::unique_ptr<SingleInterface> make_single_target() {
    return std::make_unique<SingleTarget>();
}

std::unique_ptr<DualInterface> make_dual_target() {
    return std::make_unique<DualTarget>();
}

std::unique_ptr<CastTarget> make_cast_target() {
    return std::make_unique<CastTarget>();
}
} // namespace safetyhook::test
