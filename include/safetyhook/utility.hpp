#pragma once

#include <algorithm>
#include <cstdint>
#include <type_traits>

namespace safetyhook {
template <typename T> constexpr void store(uint8_t* address, const T& value) {
    std::copy_n(reinterpret_cast<const uint8_t*>(&value), sizeof(T), address);
}

template <typename T>
concept FnPtr = requires(T f) {
    std::is_pointer_v<T>

    // 32-bit MSVC doesn't seem to think `static __thiscall` functions are functions.
#if defined(_M_X64)
        && std::is_function_v<std::remove_pointer_t<T>>
#endif
        ;
};
} // namespace safetyhook
