#pragma once

#include "safetyhook/inline_hook.hpp"
#include "safetyhook/mid_hook.hpp"

namespace safetyhook {
InlineHook create_inline(void* target, void* destination);
InlineHook create_inline(uintptr_t target, uintptr_t destination);
MidHook create_mid(void* target, MidHookFn destination);
MidHook create_mid(uintptr_t target, MidHookFn destination);
}