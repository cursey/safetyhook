#include "safetyhook/easy.hpp"

namespace safetyhook {
InlineHook create_inline(void* target, void* destination) {
    return create_inline(reinterpret_cast<uintptr_t>(target), reinterpret_cast<uintptr_t>(destination));
}

InlineHook create_inline(uintptr_t target, uintptr_t destination) {
    if (auto hook = InlineHook::create(target, destination)) {
        return std::move(*hook);
    } else {
        return {};
    }
}

MidHook create_mid(void* target, MidHookFn destination) {
    return create_mid(reinterpret_cast<uintptr_t>(target), destination);
}

MidHook create_mid(uintptr_t target, MidHookFn destination) {
    if (auto hook = MidHook::create(target, destination)) {
        return std::move(*hook);
    } else {
        return {};
    }
}
} // namespace safetyhook