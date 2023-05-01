#include <safetyhook/easy.hpp>

namespace safetyhook {
InlineHook create_inline(void* target, void* destination) {
    if (auto hook = InlineHook::create(target, destination)) {
        return std::move(*hook);
    } else {
        return {};
    }
}

MidHook create_mid(void* target, MidHookFn destination) {
    if (auto hook = MidHook::create(target, destination)) {
        return std::move(*hook);
    } else {
        return {};
    }
}

VmtHook create_vmt(void* object) {
    if (auto hook = VmtHook::create(object)) {
        return std::move(*hook);
    } else {
        return {};
    }
}
} // namespace safetyhook