/// @file safetyhook/vmt_hook.hpp
/// @brief VMT hooking classes

#pragma once

#include <cstdint>
#include <vector>

namespace safetyhook {

class VmtHook final {
public:
    [[nodiscard]] static VmtHook create(void* object);

    void reset();

    template <typename T>
    [[nodiscard]] T* hook(size_t index, T* new_function) {
        auto old_function = m_new_vmt[index];
        m_new_vmt[index] = reinterpret_cast<uint8_t*>(new_function);
        return reinterpret_cast<T*>(old_function);
    }

private:
    uint8_t** m_original_vmt{};
    std::vector<uint8_t*> m_new_vmt{};
};
}
