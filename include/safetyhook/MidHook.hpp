#pragma once

#include <memory>

namespace safetyhook {
class Factory;
class InlineHook;

struct Context64 {
    uintptr_t rflags, r15, r14, r13, r12, r11, r10, r9, r8, rdi, rsi, rdx, rcx, rbx, rax, rbp, rsp;
};

struct Context32 {
    uintptr_t eflags, edi, esi, edx, ecx, ebx, eax, ebp, esp;
};

#ifdef _M_X64
using Context = Context64;
#else
using Context = Context32;
#endif

using MidHookFn = void (*)(Context& ctx);

class MidHook final {
public:
    MidHook() = delete;
    MidHook(const MidHook&) = delete;
    MidHook(MidHook&&) noexcept = delete;
    MidHook& operator=(const MidHook&) = delete;
    MidHook& operator=(MidHook&&) noexcept = delete;

    ~MidHook();

    [[nodiscard]] auto target() const { return m_target; }
    [[nodiscard]] auto destination() const { return m_destination; }

private:
    friend Factory;

    std::shared_ptr<Factory> m_factory{};
    std::unique_ptr<InlineHook> m_hook{};
    uintptr_t m_target{};
    uintptr_t m_stub{};
    MidHookFn m_destination{};

    MidHook(std::shared_ptr<Factory> factory, uintptr_t target, MidHookFn destination);
};
} // namespace safetyhook