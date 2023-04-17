#pragma once

#include <cstdint>

namespace safetyhook {
template <typename T> constexpr void store(uint8_t* address, const T& value) {
    const auto data = reinterpret_cast<const uint8_t*>(&value);

    // Write each byte out individually to avoid undefined behavior.
    for (size_t i = 0; i < sizeof(T); ++i) {
        address[i] = data[i];
    }
}
} // namespace safetyhook