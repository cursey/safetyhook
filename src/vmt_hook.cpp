#include <safetyhook/vmt_hook.hpp>

namespace safetyhook {
VmHook::VmHook(VmHook&& other) noexcept {
    *this = std::move(other);
}

VmHook& VmHook::operator=(VmHook&& other) noexcept {
    destroy();
    m_original_vm = other.m_original_vm;
    m_new_vm = other.m_new_vm;
    m_vmt_entry = other.m_vmt_entry;
    other.m_original_vm = nullptr;
    other.m_new_vm = nullptr;
    other.m_vmt_entry = nullptr;
    return *this;
}

VmHook::~VmHook() {
    destroy();
}

void VmHook::reset() {
    *this = {};
}

void VmHook::destroy() {
    if (m_original_vm != nullptr) {
        *m_vmt_entry = m_original_vm;
        m_original_vm = nullptr;
        m_new_vm = nullptr;
        m_vmt_entry = nullptr;
    }
}

std::expected<VmtHook, VmtHook::Error> VmtHook::create(void* object) {
    VmtHook hook{};

    hook.m_object = object;
    hook.m_original_vmt = *reinterpret_cast<uint8_t***>(object);

    // Copy pointer to RTTI.
    hook.m_new_vmt.push_back(*(hook.m_original_vmt - 1));

    // Copy virtual method pointers.
    for (auto vm = hook.m_original_vmt; *vm; ++vm) {
        hook.m_new_vmt.push_back(*vm);
    }

    *reinterpret_cast<uint8_t***>(object) = hook.m_new_vmt.data() + 1;

    return hook;
}

VmtHook::VmtHook(VmtHook&& other) noexcept {
    *this = std::move(other);
}

VmtHook& VmtHook::operator=(VmtHook&& other) noexcept {
    destroy();
    m_object = other.m_object;
    m_original_vmt = other.m_original_vmt;
    m_new_vmt = std::move(other.m_new_vmt);
    other.m_object = nullptr;
    other.m_original_vmt = nullptr;
    return *this;
}

VmtHook::~VmtHook() {
    destroy();
}

void VmtHook::reset() {
    *this = {};
}

void VmtHook::destroy() {
    if (m_original_vmt != nullptr) {
        *reinterpret_cast<uint8_t***>(m_object) = m_original_vmt;
        m_original_vmt = nullptr;
        m_new_vmt.clear();
    }
}
} // namespace safetyhook