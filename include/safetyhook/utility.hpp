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

class UnprotectMemory {
public:
    UnprotectMemory() = delete;
    ~UnprotectMemory();
    UnprotectMemory(const UnprotectMemory&) = delete;
    UnprotectMemory(UnprotectMemory&& other) noexcept;
    UnprotectMemory& operator=(const UnprotectMemory&) = delete;
    UnprotectMemory& operator=(UnprotectMemory&& other) noexcept;

private:
    friend std::optional<UnprotectMemory> unprotect(uint8_t*, size_t);

    UnprotectMemory(uint8_t* address, size_t size, uint32_t original_protection)
        : m_address{address}, m_size{size}, m_original_protection{original_protection} {}

    uint8_t* m_address{};
    size_t m_size{};
    uint32_t m_original_protection{};
};

[[nodiscard]] std::optional<UnprotectMemory> unprotect(uint8_t* address, size_t size);
} // namespace safetyhook
