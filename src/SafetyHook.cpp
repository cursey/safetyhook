#include <iterator>

#include <Windows.h>

#include <disasmtypes.h>

#include <bddisasm.h>

#include "SafetyHookFactory.hpp"

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
struct Jmp {
    uint8_t prefix{0xFF};
    uint8_t opcode{0x25};
    uint32_t offset{0};
};
#include <poppack.h>

constexpr auto make_jmp(uintptr_t src, uintptr_t dst, uintptr_t data) {
    Jmp jmp{};

    jmp.offset = data - src - 6;
    *(uintptr_t*)data = dst;

    return jmp;
}

static void emit_jmp(uintptr_t src, uintptr_t dst, uintptr_t data, size_t size = sizeof(Jmp)) {
    if (size < sizeof(Jmp)) {
        return;
    }

    UnprotectMemory _{src, size};

    if (size > sizeof(Jmp)) {
        std::fill_n((uint8_t*)src, size, 0x90);
    }

    *(Jmp*)src = make_jmp(src, dst, data);
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

SafetyHook::SafetyHook(std::shared_ptr<SafetyHookFactory> manager, uintptr_t target, uintptr_t destination)
    : m_manager{manager}, m_target{follow_jmps(target)}, m_destination{follow_jmps(destination)} {
    auto ip = m_target;

    while (m_trampoline_size < sizeof(Jmp)) {
        INSTRUX ix{};

        if (!decode(&ix, ip)) {
            return;
        }

        // TODO: ensure any instructions that become part of the trampoline will function properly when moved to the
        // trampoline.

        m_trampoline_size += ix.Length;
        ip += ix.Length;
    }

    m_trampoline = m_manager->allocate(m_trampoline_size + sizeof(Jmp) + sizeof(uintptr_t));
    m_trampoline_data = m_manager->allocate_near(m_target, sizeof(uintptr_t));

    std::copy_n((const uint8_t*)m_target, m_trampoline_size, std::back_inserter(m_original_bytes));
    std::copy_n((const uint8_t*)m_target, m_trampoline_size, (uint8_t*)m_trampoline);
    emit_jmp(m_trampoline + m_trampoline_size, ip, m_trampoline + m_trampoline_size + sizeof(Jmp));
    emit_jmp(m_target, (uintptr_t)m_destination, m_trampoline_data, m_trampoline_size);
}

SafetyHook::~SafetyHook() {
    if (!ok()) {
        return;
    }

    UnprotectMemory _{m_target, m_trampoline_size};

    std::copy_n(m_original_bytes.data(), m_original_bytes.size(), (uint8_t*)m_target);
    m_manager->free(m_trampoline_data, sizeof(uintptr_t));
    m_manager->free(m_trampoline, m_trampoline_size + sizeof(Jmp) + sizeof(uintptr_t));
}
