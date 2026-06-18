/// @file safetyhook/context.hpp
/// @brief Context structure for MidHook.

#pragma once

#ifndef SAFETYHOOK_USE_CXXMODULES
#include <cstddef>
#include <cstdint>
#else
import std.compat;
#endif

#include "safetyhook/common.hpp"

namespace safetyhook {

/// @brief 128-bit XMM register.
union Xmm {
    uint8_t u8[16];
    uint16_t u16[8];
    uint32_t u32[4];
    uint64_t u64[2];
    float f32[4];
    double f64[2];
};

static_assert(sizeof(Xmm) == 16, "Xmm must be 16 bytes");

/// @brief 80-bit x87 FPU / 64-bit MMX register.
/// @note Packed to 10 bytes so it maps directly to the raw x87 register format.
/// @note The `mm` member is the low 64 bits, aliased to the MMX register.
#pragma pack(push, 1)
union Fpu {
    uint8_t u8[10];
    uint16_t u16[5];
    uint32_t u32[2];
    uint64_t u64;
    uint64_t mm;

    [[nodiscard]] float as_f32() const noexcept;
    void set_f32(float value) noexcept;

    [[nodiscard]] double as_f64() const noexcept;
    void set_f64(double value) noexcept;
};
#pragma pack(pop)

static_assert(sizeof(Fpu) == 10, "Fpu must be 10 bytes (packed)");

/// @brief Context structure for 64-bit MidHook.
/// @details This structure is used to pass the context of the hooked function to the destination allowing full access
/// to the 64-bit registers at the moment the hook is called.
/// @note rip will point to a trampoline containing the replaced instruction(s).
/// @note rsp is read-only. Modifying it will have no effect. Use trampoline_rsp to modify rsp if needed but make sure
/// the top of the stack is the rip you want to resume at.
struct Context64 {
    Xmm xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15;
    uint32_t mxcsr;
    uintptr_t rflags, r15, r14, r13, r12, r11, r10, r9, r8, rdi, rsi, rdx, rcx, rbx, rax, rbp, rsp, trampoline_rsp, rip;
};

/// @brief Context structure for 32-bit MidHook.
/// @details This structure is used to pass the context of the hooked function to the destination allowing full access
/// to the 32-bit registers at the moment the hook is called.
/// @note eip will point to a trampoline containing the replaced instruction(s).
/// @note esp is read-only. Modifying it will have no effect. Use trampoline_esp to modify esp if needed but make sure
/// the top of the stack is the eip you want to resume at.
struct Context32 {
    Xmm xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7;
    Fpu st0, st1, st2, st3, st4, st5, st6, st7;
    uint32_t mxcsr;
    uintptr_t eflags, edi, esi, edx, ecx, ebx, eax, ebp, esp, trampoline_esp, eip;
};

/// @brief Context structure for MidHook.
/// @details This structure is used to pass the context of the hooked function to the destination allowing full access
/// to the registers at the moment the hook is called.
/// @note The structure is different depending on architecture.
#if SAFETYHOOK_ARCH_X86_64
using Context = Context64;

static_assert(sizeof(Context) == 416, "Context64 size mismatch");
static_assert(offsetof(Context, xmm0) == 0, "xmm0 offset mismatch");
static_assert(offsetof(Context, xmm15) == 240, "xmm15 offset mismatch");
static_assert(offsetof(Context, mxcsr) == 256, "mxcsr offset mismatch");
static_assert(offsetof(Context, rflags) == 264, "rflags offset mismatch");
static_assert(offsetof(Context, rsp) == 392, "rsp offset mismatch");
static_assert(offsetof(Context, rip) == 408, "rip offset mismatch");
#elif SAFETYHOOK_ARCH_X86_32
using Context = Context32;

static_assert(sizeof(Context) == 256, "Context32 size mismatch");
static_assert(offsetof(Context, xmm0) == 0, "xmm0 offset mismatch");
static_assert(offsetof(Context, xmm7) == 112, "xmm7 offset mismatch");
static_assert(offsetof(Context, st0) == 128, "st0 offset mismatch");
static_assert(offsetof(Context, st7) == 198, "st7 offset mismatch");
static_assert(offsetof(Context, mxcsr) == 208, "mxcsr offset mismatch");
static_assert(offsetof(Context, eflags) == 212, "eflags offset mismatch");
static_assert(offsetof(Context, esp) == 244, "esp offset mismatch");
static_assert(offsetof(Context, eip) == 252, "eip offset mismatch");
#endif

} // namespace safetyhook