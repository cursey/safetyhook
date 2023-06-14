#pragma once

#include <algorithm>
#include <cstdint>
#include <type_traits>

namespace safetyhook {
template <typename T> constexpr void store(uint8_t* address, const T& value) {
    std::copy_n(reinterpret_cast<const uint8_t*>(&value), sizeof(T), address);
}

template <typename T>
concept FnPtr = requires(T f) { std::is_pointer_v<T>&& std::is_function_v<std::remove_pointer_t<T>>; };

bool is_executable(uint8_t* address);
} // namespace safetyhook
