#include <safetyhook/vmt_hook.hpp>

namespace safetyhook {
VmtHook VmtHook::create(void* object) {
    VmtHook hook{};

    hook.m_original_vmt = *reinterpret_cast<uint8_t***>(object);

    for (auto vmt = hook.m_original_vmt; *vmt; ++vmt) {
        hook.m_new_vmt.push_back(*vmt);
    }

    *reinterpret_cast<uint8_t***>(object) = hook.m_new_vmt.data();

    return hook;
}

void VmtHook::reset() {
    if (m_original_vmt != nullptr) {
        *reinterpret_cast<uint8_t***>(m_original_vmt) = m_original_vmt;
    }
}


}