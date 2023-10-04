/// @file safetyhook/context.hpp
/// @brief Context structure for MidHook.

#pragma once

#include <cstdint>

namespace safetyhook {
/// @brief Context structure for 64-bit MidHook.
/// @details This structure is used to pass the context of the hooked function to the destination allowing full access
/// to the 64-bit registers at the moment the hook is called.
/// @note The structure only provides access to integer registers.
struct Context64 {
    uintptr_t rflags, r15, r14, r13, r12, r11, r10, r9, r8, rdi, rsi, rdx, rcx, rbx, rax, rbp, rsp, rip;
};

/// @brief Context structure for 32-bit MidHook.
/// @details This structure is used to pass the context of the hooked function to the destination allowing full access
/// to the 32-bit registers at the moment the hook is called.
/// @note The structure only provides access to integer registers.
struct Context32 {
    uintptr_t eflags, edi, esi, edx, ecx, ebx, eax, ebp, esp, eip;
};

/// @brief Context structure for MidHook.
/// @details This structure is used to pass the context of the hooked function to the destination allowing full access
/// to the registers at the moment the hook is called.
/// @note The structure is different depending on architecture.
/// @note The structure only provides access to integer registers.
#ifdef _M_X64
using Context = Context64;
#else
using Context = Context32;
#endif

} // namespace safetyhook