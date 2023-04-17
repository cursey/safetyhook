#pragma once

#include <algorithm>
#include <cstdint>

namespace safetyhook {
template <typename T> constexpr void store(uint8_t* address, const T& value) {
    std::copy_n(reinterpret_cast<const uint8_t*>(&value), sizeof(T), address);
}
} // namespace safetyhook
