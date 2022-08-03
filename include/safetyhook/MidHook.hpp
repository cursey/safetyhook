#pragma once

#include <memory>

namespace safetyhook {
class Factory;
class InlineHook;

struct Context {
    uintptr_t rflags, r15, r14, r13, r12, r11, r10, r9, r8, rdi, rsi, rdx, rcx, rbx, rax, rbp, rsp;
};

using MidHookFn = void (*)(Context& ctx);

class MidHook final {
public:
    MidHook() = delete;
    MidHook(const MidHook&) = delete;
    MidHook(MidHook&&) = delete;
    ~MidHook();

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