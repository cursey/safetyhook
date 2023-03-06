/// @file safetyhook/easy.hpp
/// @brief Easy to use API for creating hooks.

#pragma once

#include "safetyhook/inline_hook.hpp"
#include "safetyhook/mid_hook.hpp"

namespace safetyhook {
/// @brief Easy to use API for creating an InlineHook.
/// @param target The address of the function to hook.
/// @param destination The address of the destination function.
/// @return The InlineHook object.
InlineHook create_inline(void* target, void* destination);

/// @brief Easy to use API for creating an InlineHook.
/// @param target The address of the function to hook.
/// @param destination The address of the destination function.
/// @return The InlineHook object.
InlineHook create_inline(uintptr_t target, uintptr_t destination);

/// @brief Easy to use API for creating a MidHook.
/// @param target the address of the function to hook.
/// @param destination The destination function.
/// @return The MidHook object.
MidHook create_mid(void* target, MidHookFn destination);

/// @brief Easy to use API for creating a MidHook.
/// @param target the address of the function to hook.
/// @param destination The destination function.
/// @return The MidHook object.
MidHook create_mid(uintptr_t target, MidHookFn destination);
} // namespace safetyhook