#include <algorithm>
#include <iterator>

#include <Windows.h>

#include <disasmtypes.h>

#include <bddisasm.h>

#include "safetyhook/Factory.hpp"

#include "safetyhook/InlineHook.hpp"

namespace safetyhook {
class UnprotectMemory {
public:
    UnprotectMemory(uintptr_t address, size_t size) : m_address{address}, m_size{size} {
        VirtualProtect((LPVOID)m_address, m_size, PAGE_EXECUTE_READWRITE, &m_protect);
    }

    ~UnprotectMemory() { VirtualProtect((LPVOID)m_address, m_size, m_protect, &m_protect); }

private:
    uintptr_t m_address{};
    size_t m_size{};
    DWORD m_protect{};
};

#pragma pack(push, 1)
struct JmpE9 {
    uint8_t opcode{0xE9};
    uint32_t offset{0};
};

struct JmpFF {
    uint8_t opcode0{0xFF};
    uint8_t opcode1{0x25};
    uint32_t offset{0};
};
#pragma pack(pop)

static auto make_jmp_ff(uintptr_t src, uintptr_t dst, uintptr_t data) {
    JmpFF jmp{};

    jmp.offset = static_cast<uint32_t>(data - src - sizeof(jmp));
    *(uintptr_t*)data = dst;

    return jmp;
}

static void emit_jmp_ff(uintptr_t src, uintptr_t dst, uintptr_t data, size_t size = sizeof(JmpFF)) {
    if (size < sizeof(JmpFF)) {
        return;
    }

    UnprotectMemory unprotect{src, size};

    if (size > sizeof(JmpFF)) {
        std::fill_n((uint8_t*)src, size, static_cast<uint8_t>(0x90));
    }

    *(JmpFF*)src = make_jmp_ff(src, dst, data);
}

constexpr auto make_jmp_e9(uintptr_t src, uintptr_t dst) {
    JmpE9 jmp{};

    jmp.offset = static_cast<uint32_t>(dst - src - sizeof(jmp));

    return jmp;
}

static void emit_jmp_e9(uintptr_t src, uintptr_t dst, size_t size = sizeof(JmpE9)) {
    if (size < sizeof(JmpE9)) {
        return;
    }

    UnprotectMemory unprotect{src, size};

    if (size > sizeof(JmpE9)) {
        std::fill_n((uint8_t*)src, size, static_cast<uint8_t>(0x90));
    }

    *(JmpE9*)src = make_jmp_e9(src, dst);
}

static bool decode(INSTRUX* ix, uintptr_t ip) {
#ifdef _M_X64
    constexpr uint8_t defcode = ND_CODE_64;
    constexpr uint8_t defdata = ND_DATA_64;
#else
    constexpr uint8_t defcode = ND_CODE_32;
    constexpr uint8_t defdata = ND_DATA_32;
#endif

    return ND_SUCCESS(NdDecode(ix, (const uint8_t*)ip, defcode, defdata));
}

InlineHook::InlineHook(InlineHook&& other) noexcept {
    *this = std::move(other);
}

InlineHook& InlineHook::operator=(InlineHook&& other) noexcept {
    destroy();

    std::scoped_lock lock{m_mutex, other.m_mutex};

    m_factory = std::move(other.m_factory);
    m_target = other.m_target;
    m_destination = other.m_destination;
    m_trampoline = other.m_trampoline;
    m_trampoline_size = other.m_trampoline_size;
    m_trampoline_allocation_size = other.m_trampoline_allocation_size;
    m_original_bytes = std::move(other.m_original_bytes);

    other.m_trampoline = 0;

    return *this;
}

InlineHook::~InlineHook() {
    destroy();
}

InlineHook::InlineHook(std::shared_ptr<Factory> factory, uintptr_t target, uintptr_t destination)
    : m_factory{std::move(factory)}, m_target{target}, m_destination{destination} {
    e9_hook();

#ifdef _M_X64
    if (m_trampoline == 0) {
        ff_hook();
    }
#endif
}

void InlineHook::e9_hook() {
    m_trampoline_size = 0;
    auto ip = m_target;
    std::vector<uintptr_t> desired_addresses{};

    desired_addresses.emplace_back(m_target);

    while (m_trampoline_size < sizeof(JmpE9)) {
        INSTRUX ix{};

        if (!decode(&ix, ip)) {
            return;
        }

        // TODO: Add support for expanding short jumps here. Until then, short
        // jumps within the trampoline are problematic so we just return for
        // now.
        if (ix.HasRelOffs && ix.RelOffsLength != 4) {
            return;
        }

        if (ix.IsRipRelative && ix.HasDisp && ix.DispLength == 4) {
            auto target_address = ip + ix.Length + (int32_t)ix.Displacement;
            desired_addresses.emplace_back(target_address);
        } else if (ix.HasRelOffs && ix.RelOffsLength == 4) {
            auto target_address = ip + ix.Length + (int32_t)ix.RelativeOffset;
            desired_addresses.emplace_back(target_address);
        }

        m_trampoline_size += ix.Length;
        ip += ix.Length;
    }

#ifdef _M_X64
    m_trampoline_allocation_size = m_trampoline_size + sizeof(JmpE9) + sizeof(JmpFF) + sizeof(uintptr_t);
#else
    m_trampoline_allocation_size = m_trampoline_size + sizeof(JmpE9) + sizeof(JmpE9);
#endif

    auto builder = Factory::acquire();
    m_trampoline = builder.allocate_near(desired_addresses, m_trampoline_allocation_size);

    if (m_trampoline == 0) {
        return;
    }

    std::copy_n((const uint8_t*)m_target, m_trampoline_size, std::back_inserter(m_original_bytes));
    std::copy_n((const uint8_t*)m_target, m_trampoline_size, (uint8_t*)m_trampoline);

    for (size_t i = 0; i < m_trampoline_size;) {
        INSTRUX ix{};

        if (!decode(&ix, m_target + i)) {
            builder.free(m_trampoline, m_trampoline_allocation_size);
            return;
        }

        if (ix.IsRipRelative && ix.HasDisp && ix.DispLength == 4) {
            auto target_address = m_target + i + ix.Length + (int32_t)ix.Displacement;
            auto new_disp = (int32_t)(target_address - (m_trampoline + i + ix.Length));
            *(uint32_t*)(m_trampoline + i + ix.DispOffset) = new_disp;
        } else if (ix.HasRelOffs && ix.RelOffsLength == 4) {
            auto target_address = m_target + i + ix.Length + (int32_t)ix.RelativeOffset;
            auto new_disp = (int32_t)(target_address - (m_trampoline + i + ix.Length));
            *(uint32_t*)(m_trampoline + i + ix.RelOffsOffset) = new_disp;
        }

        i += ix.Length;
    }

    // jmp from trampoline to original.
    auto src = m_trampoline + m_trampoline_size;
    auto dst = ip;
    emit_jmp_e9(src, dst);

    // jmp from original to trampoline.
    src = m_target;
    dst = m_trampoline + m_trampoline_size + sizeof(JmpE9);
    emit_jmp_e9(src, dst, m_trampoline_size);

    // jmp from trampoline to destination.
    src = m_trampoline + m_trampoline_size + sizeof(JmpE9);
    dst = m_destination;

#ifdef _M_X64
    auto data = src + sizeof(JmpFF);
    emit_jmp_ff(src, dst, data);
#else
    emit_jmp_e9(src, dst);
#endif

    for (size_t i = 0; i < m_trampoline_size; ++i) {
        builder.fix_ip(m_target + i, m_trampoline + i);
    }
}

void InlineHook::ff_hook() {
    m_trampoline_size = 0;
    auto ip = m_target;

    while (m_trampoline_size < sizeof(JmpFF) + sizeof(uintptr_t)) {
        INSTRUX ix{};

        if (!decode(&ix, ip)) {
            return;
        }

        // We can't support any instruction that is IP relative here because
        // ff_hook should only be called if e9_hook failed indicating that
        // we're likely outside the +- 2GB range.
        if (ix.IsRipRelative || ix.HasRelOffs) {
            return;
        }

        m_trampoline_size += ix.Length;
        ip += ix.Length;
    }

    auto builder = Factory::acquire();
    m_trampoline_allocation_size = m_trampoline_size + sizeof(JmpFF) + sizeof(uintptr_t) * 2;
    m_trampoline = builder.allocate(m_trampoline_allocation_size);

    if (m_trampoline == 0) {
        return;
    }

    std::copy_n((const uint8_t*)m_target, m_trampoline_size, std::back_inserter(m_original_bytes));
    std::copy_n((const uint8_t*)m_target, m_trampoline_size, (uint8_t*)m_trampoline);

    // jmp from trampoline to original.
    auto src = m_trampoline + m_trampoline_size;
    auto dst = ip;
    auto data = src + sizeof(JmpFF);
    emit_jmp_ff(src, dst, data);

    // jmp from original to trampoline.
    src = m_target;
    dst = m_destination;
    data = src + sizeof(JmpFF);
    emit_jmp_ff(src, dst, data, m_trampoline_size);

    for (size_t i = 0; i < m_trampoline_size; ++i) {
        builder.fix_ip(m_target + i, m_trampoline + i);
    }
}

void InlineHook::destroy() {
    std::scoped_lock lock{m_mutex};

    if (m_trampoline == 0) {
        return;
    }

    auto builder = Factory::acquire();
    UnprotectMemory unprotect{m_target, m_trampoline_size};

    std::copy_n(m_original_bytes.data(), m_original_bytes.size(), (uint8_t*)m_target);

    for (size_t i = 0; i < m_trampoline_size; ++i) {
        builder.fix_ip(m_trampoline + i, m_target + i);
    }

    // If the IP is on the trampolines jmp.
    builder.fix_ip(m_trampoline + m_trampoline_size, m_target + m_trampoline_size);
    builder.free(m_trampoline, m_trampoline_allocation_size);

    m_trampoline = 0;
}
} // namespace safetyhook
