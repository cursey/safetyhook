/// @file safetyhook/context.hpp
/// @brief Context structure for MidHook.

#pragma once

#ifndef SAFETYHOOK_USE_CXXMODULES
#include <cstdint>
#else
import std.compat;
#endif

#include "safetyhook/common.hpp"

namespace safetyhook {
union Xmm {
    uint8_t u8[16];
    uint16_t u16[8];
    uint32_t u32[4];
    uint64_t u64[2];
    float f32[4];
    double f64[2];
};

#if SAFETYHOOK_ARCH_X86_32

/// @brief 80-bit x87 extended-precision register (ST(n) slot from FNSAVE/FRSTOR).
/// @note The explicit integer bit (bit 63) makes direct reinterpretation as
/// double unsafe -- conversions go through as_f32/as_f64/set_f32/set_f64.
struct Fpu {
    uint8_t raw[10];

    [[nodiscard]] float as_f32() const noexcept;  ///< Read as float (via FPU fld/fstp).
    [[nodiscard]] double as_f64() const noexcept; ///< Read as double (via FPU fld/fstp).
    void set_f32(float v) noexcept;               ///< Write from float (via FPU fld/fstp).
    void set_f64(double v) noexcept;              ///< Write from double (via FPU fld/fstp).
};

/// @brief 28-byte x87 operating environment saved by FNSAVE (32-bit protected mode).
/// @details Stored opaquely so FRSTOR can replay the exact captured environment.
/// Treat as opaque: on some microarchitectures the saved env reflects the
/// post-FNSAVE reset rather than the live state. Use Context32::st_push / st_pop
/// for stack manipulation; the top() accessor is informational and may be stale.
#pragma pack(push, 1)
struct FpuEnv {
    uint16_t fcw;          ///< Control word (rounding, precision, exception masks).
    uint16_t fsw;          ///< Status word (TOP in bits 11..13, condition codes).
    uint16_t ftw;          ///< Tag word (2 bits per physical register).
    uint16_t fop;          ///< Last x87 opcode.
    uint32_t fip;          ///< Instruction pointer offset.
    uint16_t fip_selector; ///< FIP CS selector.
    uint16_t fip_reserved; ///< Reserved.
    uint32_t fdp;          ///< Data pointer offset.
    uint16_t fdp_selector; ///< FDP CS selector.
    uint16_t fdp_reserved; ///< Reserved.
    uint32_t reserved;     ///< Final 4 reserved bytes (env size = 28).

    /// @return Physical register index of ST(0), 0..7 (may reflect post-save reset).
    [[nodiscard]] uint8_t top() const noexcept { return (fsw >> 11) & 7; }
};
#pragma pack(pop)

#endif

/// @brief Context structure for 64-bit MidHook.
/// @details This structure is used to pass the context of the hooked function to the destination allowing full access
/// to the 64-bit registers at the moment the hook is called.
/// @note rip will point to a trampoline containing the replaced instruction(s).
/// @note rsp is read-only. Modifying it will have no effect. Use trampoline_rsp to modify rsp if needed but make sure
/// the top of the stack is the rip you want to resume at.
struct Context64 {
    Xmm xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15;
    uintptr_t rflags, r15, r14, r13, r12, r11, r10, r9, r8, rdi, rsi, rdx, rcx, rbx, rax, rbp, rsp, trampoline_rsp, rip;
};

/// @brief Context structure for 32-bit MidHook.
/// @details This structure is used to pass the context of the hooked function to the destination allowing full access
/// to the 32-bit registers at the moment the hook is called.
/// @note eip will point to a trampoline containing the replaced instruction(s).
/// @note esp is read-only. Modifying it will have no effect. Use trampoline_esp to modify esp if needed but make sure
/// the top of the stack is the eip you want to resume at.
/// @note The x87 FPU state is captured via FNSAVE into fpu_env + st[8] (108 bytes, logical stack order: st[0] is
/// always ST(0)). MXCSR is saved via stmxcsr. FRSTOR/ldmxcsr replay the saved image verbatim on return, so writes to
/// st[n] or mxcsr take effect for the hooked code.
struct Context32 {
#if SAFETYHOOK_ARCH_X86_32
    FpuEnv fpu_env; ///< x87 operating environment (28 bytes).
    Fpu st[8];      ///< x87 ST(0)..ST(7), logical stack order (80 bytes).
    uint32_t mxcsr; ///< SSE control/status (saved via stmxcsr).
#endif
    Xmm xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7;
    uintptr_t eflags, edi, esi, edx, ecx, ebx, eax, ebp, esp, trampoline_esp, eip;

#if SAFETYHOOK_ARCH_X86_32
    /// @brief Pop ST(0): shift ST(1..7) down into ST(0..6) (cf. `fstp st(0)`).
    /// @note Only the register-slot bytes are rotated; fpu_env (TOP, FTW, etc.) is NOT
    /// re-derived to reflect the new logical stack. FRSTOR reinstates the captured env
    /// alongside the rotated slots, so the bytes FRSTOR loads into ST(0)..ST(7) match
    /// the rotated buffer -- meaning the *values* the hooked code observes through FPU
    /// ops are correct -- but reading fpu_env.fsw / fpu_env.ftw afterward would show the
    /// pre-pop state. Prefer set_f32 / set_f64 for env-consistent single-slot writes.
    void st_pop() noexcept;

    /// @brief Push `v` as the new ST(0), shifting ST(0..6) up to ST(1..7) (cf. `fld dword`).
    /// @note Same env caveat as st_pop: slot bytes are rotated but fpu_env is not updated.
    /// @param v The value to load as the new ST(0).
    void st_push_f32(float v) noexcept;

    /// @brief Push `v` as the new ST(0), shifting ST(0..6) up to ST(1..7) (cf. `fld qword`).
    /// @note Same env caveat as st_pop: slot bytes are rotated but fpu_env is not updated.
    /// @param v The value to load as the new ST(0).
    void st_push_f64(double v) noexcept;
#endif
};

/// @brief Context structure for MidHook.
/// @details This structure is used to pass the context of the hooked function to the destination allowing full access
/// to the registers at the moment the hook is called.
/// @note The structure is different depending on architecture.
/// @note The structure exposes integer, SSE (XMM), and (on x86-32) x87 FPU + MXCSR state.
#if SAFETYHOOK_ARCH_X86_64
using Context = Context64;
#elif SAFETYHOOK_ARCH_X86_32
using Context = Context32;

static_assert(sizeof(FpuEnv) == 28, "FpuEnv must match the 28-byte FNSAVE environment image");
static_assert(sizeof(Fpu) == 10, "Fpu must match the 10-byte x87 register slot");
#endif
} // namespace safetyhook