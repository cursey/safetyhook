#pragma once

#include <cstdint>

namespace safetyhook {
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
} // namespace safetyhook