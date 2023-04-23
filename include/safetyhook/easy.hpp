/// @file safetyhook/easy.hpp
/// @brief Easy to use API for creating hooks.

#pragma once

#include <safetyhook/inline_hook.hpp>
#include <safetyhook/mid_hook.hpp>

namespace safetyhook {
/// @brief Easy to use API for creating an InlineHook.
/// @param target The address of the function to hook.
/// @param destination The address of the destination function.
/// @return The InlineHook object.
[[nodiscard]] InlineHook create_inline(void* target, void* destination);

/// @brief Easy to use API for creating an InlineHook.
/// @tparam T The type of the function to hook.
/// @param target The address of the function to hook.
/// @param destination The address of the destination function.
/// @return The InlineHook object.
template <typename T>
    requires std::is_function_v<T>
[[nodiscard]] InlineHook create_inline(T* target, T* destination) {
    return create_inline(reinterpret_cast<void*>(target), reinterpret_cast<void*>(destination));
}

/// @brief Easy to use API for creating a MidHook.
/// @param target the address of the function to hook.
/// @param destination The destination function.
/// @return The MidHook object.
[[nodiscard]] MidHook create_mid(void* target, MidHookFn destination);

/// @brief Easy to use API for creating a MidHook.
/// @tparam T The type of the function to hook.
/// @param target the address of the function to hook.
/// @param destination The destination function.
/// @return The MidHook object.
template <typename T>
    requires std::is_function_v<T>
[[nodiscard]] MidHook create_mid(T* target, MidHookFn destination) {
    return create_mid(reinterpret_cast<void*>(target), destination);
}
} // namespace safetyhook