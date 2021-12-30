#include <iterator>

#include <Windows.h>

#include <disasmtypes.h>

#include <bddisasm.h>

#include "SafetyHookFactory.hpp"
#include "ThreadFreezer.hpp"

#include "SafetyHook.hpp"

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

#include <pshpack1.h>
struct JmpE9 {
    uint8_t opcode{0xE9};
    uint32_t offset{0};
};

struct JmpFF {
    uint8_t opcode0{0xFF};
    uint8_t opcode1{0x25};
    uint32_t offset{0};
};
#include <poppack.h>

constexpr auto make_jmp_ff(uintptr_t src, uintptr_t dst, uintptr_t data) {
    JmpFF jmp{};

    jmp.offset = data - src - sizeof(jmp);
    *(uintptr_t*)data = dst;

    return jmp;
}

static void emit_jmp_ff(uintptr_t src, uintptr_t dst, uintptr_t data, size_t size = sizeof(JmpFF)) {
    if (size < sizeof(JmpFF)) {
        return;
    }

    UnprotectMemory _{src, size};

    if (size > sizeof(JmpFF)) {
        std::fill_n((uint8_t*)src, size, 0x90);
    }

    *(JmpFF*)src = make_jmp_ff(src, dst, data);
}

constexpr auto make_jmp_e9(uintptr_t src, uintptr_t dst) {
    JmpE9 jmp{};

    jmp.offset = dst - src - sizeof(jmp);

    return jmp;
}

constexpr void emit_jmp_e9(uintptr_t src, uintptr_t dst, size_t size = sizeof(JmpE9)) {
    if (size < sizeof(JmpE9)) {
        return;
    }

    UnprotectMemory _{src, size};

    if (size > sizeof(JmpE9)) {
        std::fill_n((uint8_t*)src, size, 0x90);
    }

    *(JmpE9*)src = make_jmp_e9(src, dst);
}

constexpr auto follow_offset_at(uintptr_t address) {
    auto offset = *(int*)address;
    auto rip = address + 4;
    return rip + offset;
}

static bool decode(INSTRUX* ix, uintptr_t ip) {
#ifdef _M_X64
    constexpr uint8_t defcode = ND_CODE_64;
    constexpr uint8_t defdata = ND_DATA_64;
#else
    constexpr uint8_t defcode = ND_CODE_32;
    constexpr uint8_t defdata = ND_DATA_32;
#endif

    auto status = NdDecode(ix, (const uint8_t*)ip, defcode, defdata);

    return ND_SUCCESS(status);
}

static uintptr_t follow_jmps(uintptr_t ip) {
    auto followed_jmp = false;

    do {
        followed_jmp = false;

        INSTRUX ix{};

        if (!decode(&ix, ip)) {
            return 0;
        }

        if (ix.InstructionBytes[0] == 0xE9) {
            ip = follow_offset_at(ip + 1);
            followed_jmp = true;
        } else if (ix.InstructionBytes[0] == 0xFF && ix.InstructionBytes[1] == 0x25) {
            ip = *(uintptr_t*)follow_offset_at(ip + 2);
            followed_jmp = true;
        }
    } while (followed_jmp);

    return ip;
}

SafetyHook::SafetyHook(std::shared_ptr<SafetyHookFactory> factory, uintptr_t target, uintptr_t destination)
    : m_factory{factory}, m_target{target}, m_destination{destination} {
    auto active_factory = factory->m_active_factory;
    auto ip = m_target;
    std::vector<uintptr_t> desired_addresses{};

    desired_addresses.emplace_back(m_target);

    while (m_trampoline_size < sizeof(JmpE9)) {
        INSTRUX ix{};

        if (!decode(&ix, ip)) {
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

    m_trampoline_allocation_size = m_trampoline_size + sizeof(JmpE9) + sizeof(JmpFF) + sizeof(uintptr_t);
    m_trampoline = active_factory->factory->allocate_near(desired_addresses, m_trampoline_allocation_size);

    std::copy_n((const uint8_t*)m_target, m_trampoline_size, std::back_inserter(m_original_bytes));
    std::copy_n((const uint8_t*)m_target, m_trampoline_size, (uint8_t*)m_trampoline);

    for (size_t i = 0; i < m_trampoline_size;) {
        INSTRUX ix{};

        if (!decode(&ix, m_target + i)) {
            active_factory->factory->free(m_trampoline, m_trampoline_allocation_size);
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
    auto data = src + sizeof(JmpFF);
    emit_jmp_ff(src, dst, data);

    for (auto i = 0; i < m_trampoline_size; ++i) {
        active_factory->threads.fix_ip(m_target + i, m_trampoline + i);
    }
}

SafetyHook::~SafetyHook() {
    if (!ok()) {
        return;
    }

    auto active_factory = m_factory->acquire();
    UnprotectMemory _{m_target, m_trampoline_size};

    std::copy_n(m_original_bytes.data(), m_original_bytes.size(), (uint8_t*)m_target);

    for (auto i = 0; i < m_trampoline_size; ++i) {
        active_factory.threads.fix_ip(m_trampoline + i, m_target + i);
    }

    // If the IP is on the trampolines jmp.
    active_factory.threads.fix_ip(m_trampoline + m_trampoline_size, m_target + m_trampoline_size);
    active_factory.factory->free(m_trampoline, m_trampoline_allocation_size);
}
