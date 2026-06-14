#include <cstring>

#include "safetyhook/os.hpp"

#include "safetyhook/vmt_hook.hpp"

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

    const auto original_vmt = *reinterpret_cast<uint8_t***>(object);
    hook.m_objects.emplace(object, original_vmt);

    // Count the number of virtual method pointers. We start at VMT_HEADER to account for
    // the vtable prefix entries (offset-to-top + RTTI ptr on Itanium, RTTICompleteObjectLocator* on MSVC).
    auto num_vmt_entries = VMT_HEADER;

    for (auto vm = original_vmt; is_executable(*vm); ++vm) {
        ++num_vmt_entries;
    }

    auto size = num_vmt_entries * sizeof(uint8_t*);

    // Allocate memory for the new VMT.
    auto allocation = Allocator::global()->allocate(size);

    if (!allocation) {
        return std::unexpected{Error::bad_allocation(allocation.error())};
    }

    hook.m_new_vmt_allocation = std::make_shared<Allocation>(std::move(*allocation));
    hook.m_new_vmt = reinterpret_cast<uint8_t**>(hook.m_new_vmt_allocation->data());

    // Copy RTTI header and virtual method pointers.
    std::memcpy(hook.m_new_vmt, original_vmt - VMT_HEADER, size);

    *reinterpret_cast<uint8_t***>(object) = &hook.m_new_vmt[VMT_HEADER];

    return hook;
}

VmtHook::VmtHook(VmtHook&& other) noexcept {
    *this = std::move(other);
}

VmtHook& VmtHook::operator=(VmtHook&& other) noexcept {
    destroy();
    m_objects = std::move(other.m_objects);
    m_new_vmt_allocation = std::move(other.m_new_vmt_allocation);
    m_new_vmt = other.m_new_vmt;
    other.m_new_vmt = nullptr;
    return *this;
}

VmtHook::~VmtHook() {
    destroy();
}

void VmtHook::apply(void* object) {
    m_objects.emplace(object, *reinterpret_cast<uint8_t***>(object));
    *reinterpret_cast<uint8_t***>(object) = &m_new_vmt[VMT_HEADER];
}

void VmtHook::remove(void* object) {
    const auto search = m_objects.find(object);

    if (search == m_objects.end()) {
        return;
    }

    const auto original_vmt = search->second;

    if (!vm_is_writable(reinterpret_cast<uint8_t*>(object), sizeof(void*))) {
        m_objects.erase(search);
        return;
    }

    if (*reinterpret_cast<uint8_t***>(object) != &m_new_vmt[VMT_HEADER]) {
        m_objects.erase(search);
        return;
    }

    *reinterpret_cast<uint8_t***>(object) = original_vmt;

    m_objects.erase(search);
}

void VmtHook::reset() {
    *this = {};
}

void VmtHook::destroy() {
    for (const auto [object, original_vmt] : m_objects) {
        if (!vm_is_writable(reinterpret_cast<uint8_t*>(object), sizeof(void*))) {
            continue;
        }

        if (*reinterpret_cast<uint8_t***>(object) != &m_new_vmt[VMT_HEADER]) {
            continue;
        }

        *reinterpret_cast<uint8_t***>(object) = original_vmt;
    }

    m_objects.clear();
    m_new_vmt_allocation.reset();
    m_new_vmt = nullptr;
}
} // namespace safetyhook
