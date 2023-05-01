#include <Windows.h>

#include <safetyhook/allocator.hpp>
#include <safetyhook/thread_freezer.hpp>

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
    m_new_vmt_allocation = std::move(other.m_new_vmt_allocation);
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
        m_new_vmt_allocation.reset();
    }
}

std::expected<VmtHook, VmtHook::Error> VmtHook::create(void* object) {
    VmtHook hook{};

    hook.m_object = object;
    hook.m_original_vmt = *reinterpret_cast<uint8_t***>(object);

    auto num_vmt_entries = 1;

    for (auto vm = hook.m_original_vmt; *vm; ++vm) {
        ++num_vmt_entries;
    }

    auto allocation = Allocator::global()->allocate(num_vmt_entries * sizeof(uint8_t*));

    if (!allocation) {
        return std::unexpected{Error::bad_allocation(allocation.error())};
    }

    hook.m_new_vmt_allocation = std::make_shared<Allocation>(std::move(*allocation));
    hook.m_new_vmt = reinterpret_cast<uint8_t**>(hook.m_new_vmt_allocation->data());

    // Copy pointer to RTTI.
    hook.m_new_vmt[0] = hook.m_original_vmt[-1];

    // Copy virtual method pointers.
    for (auto i = 0; i < num_vmt_entries - 1; ++i) {
        hook.m_new_vmt[i + 1] = hook.m_original_vmt[i];
    }

    *reinterpret_cast<uint8_t***>(object) = &hook.m_new_vmt[1]; // hook.m_new_vmt.data() + 1;

    return hook;
}

VmtHook::VmtHook(VmtHook&& other) noexcept {
    *this = std::move(other);
}

VmtHook& VmtHook::operator=(VmtHook&& other) noexcept {
    destroy();
    m_object = other.m_object;
    m_original_vmt = other.m_original_vmt;
    m_new_vmt_allocation = std::move(other.m_new_vmt_allocation);
    m_new_vmt = other.m_new_vmt;
    other.m_object = nullptr;
    other.m_original_vmt = nullptr;
    other.m_new_vmt = nullptr;
    return *this;
}

VmtHook::~VmtHook() {
    destroy();
}

void VmtHook::reset() {
    *this = {};
}

void VmtHook::destroy() {
    if (m_original_vmt == nullptr) {
        return;
    }

    execute_while_frozen([this] {
        if (IsBadWritePtr(m_object, sizeof(void*))) {
            return;
        }

        if (*reinterpret_cast<uint8_t***>(m_object) != &m_new_vmt[1]) {
            return;
        }

        *reinterpret_cast<uint8_t***>(m_object) = m_original_vmt;
    });

    m_original_vmt = nullptr;
    m_new_vmt_allocation.reset();
    m_new_vmt = nullptr;
}
} // namespace safetyhook