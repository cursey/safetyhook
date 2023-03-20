#include <iterator>

#include <Windows.h>

#if __has_include(<Zydis/Zydis.h>)
#include <Zydis/Zydis.h>
#elif __has_include(<Zydis.h>)
#include <Zydis.h>
#else
#error "Zydis not found"
#endif

#include <safetyhook/allocator.hpp>
#include <safetyhook/thread_freezer.hpp>

#include <safetyhook/inline_hook.hpp>

namespace safetyhook {
class UnprotectMemory {
public:
    UnprotectMemory(uintptr_t address, size_t size) : m_address{address}, m_size{size} {
        VirtualProtect(reinterpret_cast<LPVOID>(m_address), m_size, PAGE_EXECUTE_READWRITE, &m_protect);
    }

    ~UnprotectMemory() { VirtualProtect(reinterpret_cast<LPVOID>(m_address), m_size, m_protect, &m_protect); }

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

#if defined(_M_X64)
struct JmpFF {
    uint8_t opcode0{0xFF};
    uint8_t opcode1{0x25};
    uint32_t offset{0};
};

struct TrampolineEpilogueE9 {
    JmpE9 jmp_to_original{};
    JmpFF jmp_to_destination{};
    uint64_t destination_address{};
};

struct TrampolineEpilogueFF {
    JmpFF jmp_to_original{};
    uint64_t original_address{};
};
#elif defined(_M_IX86)
struct TrampolineEpilogueE9 {
    JmpE9 jmp_to_original{};
    JmpE9 jmp_to_destination{};
};
#endif
#pragma pack(pop)

#ifdef _M_X64
static auto make_jmp_ff(uintptr_t src, uintptr_t dst, uintptr_t data) {
    JmpFF jmp{};

    jmp.offset = static_cast<uint32_t>(data - src - sizeof(jmp));
    *reinterpret_cast<uintptr_t*>(data) = dst;

    return jmp;
}

static void emit_jmp_ff(uintptr_t src, uintptr_t dst, uintptr_t data, size_t size = sizeof(JmpFF)) {
    if (size < sizeof(JmpFF)) {
        return;
    }

    UnprotectMemory unprotect{src, size};

    if (size > sizeof(JmpFF)) {
        std::fill_n(reinterpret_cast<uint8_t*>(src), size, static_cast<uint8_t>(0x90));
    }

    *reinterpret_cast<JmpFF*>(src) = make_jmp_ff(src, dst, data);
}
#endif

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
        std::fill_n(reinterpret_cast<uint8_t*>(src), size, static_cast<uint8_t>(0x90));
    }

    *reinterpret_cast<JmpE9*>(src) = make_jmp_e9(src, dst);
}

static bool decode(ZydisDecodedInstruction* ix, uintptr_t ip) {
    ZydisDecoder decoder{};
    ZyanStatus status{};

#if defined(_M_X64)
    status = ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
#elif defined(_M_IX86)
    status = ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);
#else
#error "Unsupported architecture"
#endif

    if (!ZYAN_SUCCESS(status)) {
        return false;
    }

    return ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&decoder, nullptr, reinterpret_cast<const void*>(ip), 15, ix));
}

std::expected<InlineHook, InlineHook::Error> InlineHook::create(void* target, void* destination) {
    return create(Allocator::global(), target, destination);
}

std::expected<InlineHook, InlineHook::Error> InlineHook::create(uintptr_t target, uintptr_t destination) {
    return create(Allocator::global(), target, destination);
}

std::expected<InlineHook, InlineHook::Error> InlineHook::create(
    const std::shared_ptr<Allocator>& allocator, void* target, void* destination) {
    return create(allocator, reinterpret_cast<uintptr_t>(target), reinterpret_cast<uintptr_t>(destination));
}

std::expected<InlineHook, InlineHook::Error> InlineHook::create(
    const std::shared_ptr<Allocator>& allocator, uintptr_t target, uintptr_t destination) {
    InlineHook hook{};

    if (const auto setup_result = hook.setup(allocator, target, destination); !setup_result) {
        return std::unexpected{setup_result.error()};
    }

    return hook;
}

InlineHook::InlineHook(InlineHook&& other) noexcept {
    *this = std::move(other);
}

InlineHook& InlineHook::operator=(InlineHook&& other) noexcept {
    if (this != &other) {
        destroy();

        std::scoped_lock lock{m_mutex, other.m_mutex};

        m_target = other.m_target;
        m_destination = other.m_destination;
        m_trampoline = std::move(other.m_trampoline);
        m_trampoline_size = other.m_trampoline_size;
        m_original_bytes = std::move(other.m_original_bytes);

        other.m_target = 0;
        other.m_destination = 0;
        other.m_trampoline_size = 0;
    }

    return *this;
}

InlineHook::~InlineHook() {
    destroy();
}

void InlineHook::reset() {
    *this = {};
}

std::expected<void, InlineHook::Error> InlineHook::setup(
    const std::shared_ptr<Allocator>& allocator, uintptr_t target, uintptr_t destination) {
    m_target = target;
    m_destination = destination;

    if (const auto e9_result = e9_hook(allocator); !e9_result) {
#ifdef _M_X64
        if (const auto ff_result = ff_hook(allocator); !ff_result) {
            return ff_result;
        }
#else
        return e9_result;
#endif
    }

    return {};
}

std::expected<void, InlineHook::Error> InlineHook::e9_hook(const std::shared_ptr<Allocator>& allocator) {
    m_original_bytes.clear();
    m_trampoline_size = sizeof(TrampolineEpilogueE9);

    std::vector<uintptr_t> desired_addresses{m_target};
    ZydisDecodedInstruction ix{};

    for (uintptr_t ip = m_target; ip < m_target + sizeof(JmpE9); ip += ix.length) {
        if (!decode(&ix, ip)) {
            return std::unexpected{Error::failed_to_decode_instruction(ip)};
        }

        m_trampoline_size += ix.length;
        m_original_bytes.insert(
            m_original_bytes.end(), reinterpret_cast<uint8_t*>(ip), reinterpret_cast<uint8_t*>(ip) + ix.length);

        const auto is_relative = (ix.attributes & ZYDIS_ATTRIB_IS_RELATIVE) != 0;

        if (is_relative) {
            if (ix.raw.disp.size == 32) {
                const auto target_address = ip + ix.length + static_cast<int32_t>(ix.raw.disp.value);
                desired_addresses.emplace_back(target_address);
            } else if (ix.raw.imm[0].size == 32) {
                const auto target_address = ip + ix.length + static_cast<int32_t>(ix.raw.imm[0].value.s);
                desired_addresses.emplace_back(target_address);
            } else if (ix.meta.category == ZYDIS_CATEGORY_COND_BR && ix.meta.branch_type == ZYDIS_BRANCH_TYPE_SHORT) {
                const auto target_address = ip + ix.length + static_cast<int32_t>(ix.raw.imm[0].value.s);
                desired_addresses.emplace_back(target_address);
                m_trampoline_size += 4; // near conditional branches are 4 bytes larger.
            } else if (ix.meta.category == ZYDIS_CATEGORY_UNCOND_BR && ix.meta.branch_type == ZYDIS_BRANCH_TYPE_SHORT) {
                const auto target_address = ip + ix.length + static_cast<int32_t>(ix.raw.imm[0].value.s);
                desired_addresses.emplace_back(target_address);
                m_trampoline_size += 3; // near unconditional branches are 3 bytes larger.
            } else {
                return std::unexpected{Error::unsupported_instruction_in_trampoline(ip)};
            }
        }
    }

    auto trampoline_allocation = allocator->allocate_near(desired_addresses, m_trampoline_size);

    if (!trampoline_allocation) {
        return std::unexpected{Error::bad_allocation(trampoline_allocation.error())};
    }

    m_trampoline = std::move(*trampoline_allocation);

    for (uintptr_t ip = m_target, tramp_ip = m_trampoline.address(); ip < m_target + m_original_bytes.size();
         ip += ix.length) {
        if (!decode(&ix, ip)) {
            m_trampoline.free();
            return std::unexpected{Error::failed_to_decode_instruction(ip)};
        }

        const auto is_relative = (ix.attributes & ZYDIS_ATTRIB_IS_RELATIVE) != 0;

        if (is_relative && ix.raw.disp.size == 32) {
            std::copy_n(reinterpret_cast<uint8_t*>(ip), ix.length, reinterpret_cast<uint8_t*>(tramp_ip));
            const auto target_address = ip + ix.length + static_cast<int32_t>(ix.raw.disp.value);
            const auto new_disp = static_cast<int32_t>(target_address - (tramp_ip + ix.length));
            *reinterpret_cast<int32_t*>(tramp_ip + ix.raw.disp.offset) = new_disp;
            tramp_ip += ix.length;
        } else if (is_relative && ix.raw.imm[0].size == 32) {
            std::copy_n(reinterpret_cast<uint8_t*>(ip), ix.length, reinterpret_cast<uint8_t*>(tramp_ip));
            const auto target_address = ip + ix.length + static_cast<int32_t>(ix.raw.imm[0].value.s);
            const auto new_disp = static_cast<int32_t>(target_address - (tramp_ip + ix.length));
            *reinterpret_cast<int32_t*>(tramp_ip + ix.raw.imm[0].offset) = new_disp;
            tramp_ip += ix.length;
        } else if (ix.meta.category == ZYDIS_CATEGORY_COND_BR && ix.meta.branch_type == ZYDIS_BRANCH_TYPE_SHORT) {
            const auto target_address = ip + ix.length + static_cast<int32_t>(ix.raw.imm[0].value.s);
            auto new_disp = static_cast<int32_t>(target_address - (tramp_ip + 6));

            // Handle the case where the target is now in the trampoline.
            if (target_address < m_target + m_original_bytes.size()) {
                new_disp = static_cast<int32_t>(ix.raw.imm[0].value.s);
            }

            *reinterpret_cast<uint8_t*>(tramp_ip) = 0x0F;
            *reinterpret_cast<uint8_t*>(tramp_ip + 1) = 0x10 + ix.opcode;
            *reinterpret_cast<int32_t*>(tramp_ip + 2) = new_disp;
            tramp_ip += 6;
        } else if (ix.meta.category == ZYDIS_CATEGORY_UNCOND_BR && ix.meta.branch_type == ZYDIS_BRANCH_TYPE_SHORT) {
            const auto target_address = ip + ix.length + static_cast<int32_t>(ix.raw.imm[0].value.s);
            auto new_disp = static_cast<int32_t>(target_address - (tramp_ip + 5));

            // Handle the case where the target is now in the trampoline.
            if (target_address < m_target + m_original_bytes.size()) {
                new_disp = static_cast<int32_t>(ix.raw.imm[0].value.s);
            }

            *reinterpret_cast<uint8_t*>(tramp_ip) = 0xE9;
            *reinterpret_cast<int32_t*>(tramp_ip + 1) = new_disp;
            tramp_ip += 5;
        } else {
            std::copy_n(reinterpret_cast<uint8_t*>(ip), ix.length, reinterpret_cast<uint8_t*>(tramp_ip));
            tramp_ip += ix.length;
        }
    }

    auto trampoline_epilogue = reinterpret_cast<TrampolineEpilogueE9*>(
        m_trampoline.address() + m_trampoline_size - sizeof(TrampolineEpilogueE9));

    // jmp from trampoline to original.
    auto src = reinterpret_cast<uintptr_t>(&trampoline_epilogue->jmp_to_original);
    auto dst = m_target + m_original_bytes.size();
    emit_jmp_e9(src, dst);

    // jmp from trampoline to destination.
    src = reinterpret_cast<uintptr_t>(&trampoline_epilogue->jmp_to_destination);
    dst = m_destination;

#ifdef _M_X64
    auto data = reinterpret_cast<uintptr_t>(&trampoline_epilogue->destination_address);
    emit_jmp_ff(src, dst, data);
#else
    emit_jmp_e9(src, dst);
#endif

    // jmp from original to trampoline.
    ThreadFreezer freezer{};

    src = m_target;
    dst = reinterpret_cast<uintptr_t>(&trampoline_epilogue->jmp_to_destination);
    emit_jmp_e9(src, dst, m_original_bytes.size());

    for (size_t i = 0; i < m_original_bytes.size(); ++i) {
        freezer.fix_ip(m_target + i, m_trampoline.address() + i);
    }

    return {};
}

#ifdef _M_X64
std::expected<void, InlineHook::Error> InlineHook::ff_hook(const std::shared_ptr<Allocator>& allocator) {
    m_original_bytes.clear();
    m_trampoline_size = sizeof(TrampolineEpilogueFF);
    ZydisDecodedInstruction ix{};

    for (auto ip = m_target; ip < m_target + sizeof(JmpFF) + sizeof(uintptr_t); ip += ix.length) {
        if (!decode(&ix, ip)) {
            return std::unexpected{Error::failed_to_decode_instruction(ip)};
        }

        // We can't support any instruction that is IP relative here because
        // ff_hook should only be called if e9_hook failed indicating that
        // we're likely outside the +- 2GB range.
        if (ix.attributes & ZYDIS_ATTRIB_IS_RELATIVE) {
            return std::unexpected{Error::ip_relative_instruction_out_of_range(ip)};
        }

        m_original_bytes.insert(
            m_original_bytes.end(), reinterpret_cast<uint8_t*>(ip), reinterpret_cast<uint8_t*>(ip + ix.length));
        m_trampoline_size += ix.length;
    }

    auto trampoline_allocation = allocator->allocate(m_trampoline_size);

    if (!trampoline_allocation) {
        return std::unexpected{Error::bad_allocation(trampoline_allocation.error())};
    }

    m_trampoline = std::move(*trampoline_allocation);

    std::copy(m_original_bytes.begin(), m_original_bytes.end(), reinterpret_cast<uint8_t*>(m_trampoline.address()));

    const auto trampoline_epilogue = reinterpret_cast<TrampolineEpilogueFF*>(
        m_trampoline.address() + m_trampoline_size - sizeof(TrampolineEpilogueFF));

    // jmp from trampoline to original.
    auto src = reinterpret_cast<uintptr_t>(&trampoline_epilogue->jmp_to_original);
    auto dst = m_target + m_original_bytes.size();
    auto data = reinterpret_cast<uintptr_t>(&trampoline_epilogue->original_address);
    emit_jmp_ff(src, dst, data);

    // jmp from original to trampoline.
    ThreadFreezer freezer{};

    src = m_target;
    dst = m_destination;
    data = src + sizeof(JmpFF);
    emit_jmp_ff(src, dst, data, m_original_bytes.size());

    for (size_t i = 0; i < m_original_bytes.size(); ++i) {
        freezer.fix_ip(m_target + i, m_trampoline.address() + i);
    }

    return {};
}
#endif

void InlineHook::destroy() {
    std::scoped_lock lock{m_mutex};

    if (!m_trampoline) {
        return;
    }

    ThreadFreezer freezer{};
    UnprotectMemory unprotect{m_target, m_original_bytes.size()};

    std::copy(m_original_bytes.begin(), m_original_bytes.end(), reinterpret_cast<uint8_t*>(m_target));

    for (size_t i = 0; i < m_trampoline_size; ++i) {
        freezer.fix_ip(m_trampoline.address() + i, m_target + i);
    }

    m_trampoline.free();
}
} // namespace safetyhook
