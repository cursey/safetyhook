#include <xbyak/xbyak.h>

#include <boost/ut.hpp>
#include <safetyhook.hpp>

using namespace boost::ut;
using namespace Xbyak::util;

#if SAFETYHOOK_ARCH_X86_32
// Write a float value into an Fpu register (converts to 80-bit extended).
using SetFpuFn = void (*)(safetyhook::Fpu&, float);

auto make_set_fpu() {
    static Xbyak::CodeGenerator cg{};

    cg.reset();

    cg.mov(eax, dword[esp + 4]);
    cg.fld(dword[esp + 8]);
    cg.db(0xDB); // fstp tbyte ptr [eax]
    cg.db(0x38);
    cg.ret();

    return cg.getCode<SetFpuFn>();
}

// Read an Fpu register back as a float (converts from 80-bit extended).
using GetFpuFn = float (*)(safetyhook::Fpu&);

auto make_get_fpu() {
    static Xbyak::CodeGenerator cg{};

    cg.reset();

    cg.mov(eax, dword[esp + 4]);
    cg.db(0xDB); // fld tbyte ptr [eax]
    cg.db(0x28);
    cg.sub(esp, 4);
    cg.fstp(dword[esp]);
    cg.fld(dword[esp]);
    cg.add(esp, 4);
    cg.ret();

    return cg.getCode<GetFpuFn>();
}

// Write a double value into an Fpu register (converts to 80-bit extended).
using SetFpuFnD = void (*)(safetyhook::Fpu&, double);

auto make_set_fpu_d() {
    static Xbyak::CodeGenerator cg{};

    cg.reset();

    cg.mov(eax, dword[esp + 4]);
    cg.fld(qword[esp + 8]);
    cg.db(0xDB); // fstp tbyte ptr [eax]
    cg.db(0x38);
    cg.ret();

    return cg.getCode<SetFpuFnD>();
}

// Read an Fpu register back as a double (converts from 80-bit extended).
using GetFpuFnD = double (*)(safetyhook::Fpu&);

auto make_get_fpu_d() {
    static Xbyak::CodeGenerator cg{};

    cg.reset();

    cg.mov(eax, dword[esp + 4]);
    cg.db(0xDB); // fld tbyte ptr [eax]
    cg.db(0x28);
    cg.sub(esp, 8);
    cg.fstp(qword[esp]);
    cg.fld(qword[esp]);
    cg.add(esp, 8);
    cg.ret();

    return cg.getCode<GetFpuFnD>();
}
#endif

static suite<"mid hook"> mid_hook_tests = [] {
    "Mid hook to change a register"_test = [] {
        struct Target {
            SAFETYHOOK_NOINLINE static int SAFETYHOOK_FASTCALL add_42(int a) { return a + 42; }
        };

        expect(Target::add_42(0) == 42_i);

        static SafetyHookMid hook;

        struct Hook {
            static void add_42(SafetyHookContext& ctx) {
#if SAFETYHOOK_OS_WINDOWS
#if SAFETYHOOK_ARCH_X86_64
                ctx.rcx = 1337 - 42;
#elif SAFETYHOOK_ARCH_X86_32
                ctx.ecx = 1337 - 42;
#endif
#elif SAFETYHOOK_OS_LINUX
#if SAFETYHOOK_ARCH_X86_64
                ctx.rdi = 1337 - 42;
#elif SAFETYHOOK_ARCH_X86_32
                ctx.edi = 1337 - 42;
#endif
#endif
            }
        };

        auto hook_result = SafetyHookMid::create(Target::add_42, Hook::add_42);

        expect(hook_result.has_value());

        hook = std::move(*hook_result);

        expect(Target::add_42(1) == 1337_i);

        hook.reset();

        expect(Target::add_42(2) == 44_i);
    };

#if SAFETYHOOK_ARCH_X86_64
    "Mid hook to change an XMM register"_test = [] {
        struct Target {
            SAFETYHOOK_NOINLINE static float SAFETYHOOK_FASTCALL add_42(float a) { return a + 0.42f; }
        };

        expect(Target::add_42(0.0f) == 0.42_f);

        static SafetyHookMid hook;

        struct Hook {
            static void add_42(SafetyHookContext& ctx) { ctx.xmm0.f32[0] = 1337.0f - 0.42f; }
        };

        auto hook_result = SafetyHookMid::create(Target::add_42, Hook::add_42);

        expect(hook_result.has_value());

        hook = std::move(*hook_result);

        expect(Target::add_42(1.0f) == 1337.0_f);

        hook.reset();

        expect(Target::add_42(2.0f) == 2.42_f);
    };

    "Mid hook MXCSR"_test = [] {
        // Load MXCSR from arg, then return cvtss2si(3.5f).
        // Default round-to-nearest gives 4, round-down gives 3.
        Xbyak::CodeGenerator cg{};
        Xbyak::Label hook_label{};

#if SAFETYHOOK_OS_WINDOWS
        cg.mov(eax, ecx); // Arg: uint32_t mxcsr value.
#elif SAFETYHOOK_OS_LINUX
        cg.mov(eax, edi); // Arg: uint32_t mxcsr value.
#endif

        cg.push(rax);
        cg.ldmxcsr(dword[rsp]);
        cg.add(rsp, 8);
        cg.L(hook_label);
        cg.nop(5, false);
        cg.mov(eax, 0x40600000); // 3.5f raw bits.
        cg.movd(xmm0, eax);
        cg.cvtss2si(eax, xmm0);
        cg.ret();

        auto target = cg.getCode<uint32_t (*)(uint32_t)>();
        auto hook_point = const_cast<void*>(reinterpret_cast<const void*>(hook_label.getAddress()));

        static uint32_t captured{};

        constexpr uint32_t round_down = 0x3F80;

        expect(target(0x1F80u) == 4_u);
        expect(target(round_down) == 3_u);

        struct ReadHook {
            static void fn(SafetyHookContext& ctx) { captured = ctx.mxcsr; }
        };

        static SafetyHookMid read_hook{};

        auto read_result = SafetyHookMid::create(hook_point, ReadHook::fn);

        expect(read_result.has_value());

        read_hook = std::move(*read_result);

        target(round_down);

        expect(captured == round_down);

        read_hook.reset();

        struct WriteHook {
            static void fn(SafetyHookContext& ctx) { ctx.mxcsr = round_down; }
        };

        static SafetyHookMid write_hook{};

        auto write_result = SafetyHookMid::create(hook_point, WriteHook::fn);

        expect(write_result.has_value());

        write_hook = std::move(*write_result);

        expect(target(0x1F80u) == 3_u);

        write_hook.reset();

        expect(target(0x1F80u) == 4_u);
    };
#endif

#if SAFETYHOOK_ARCH_X86_32
    "Mid hook x87 ST(0..7) (f32)"_test = [] {
        // Load eight floats onto x87 stack, hook point, then pop them to out[].
        Xbyak::CodeGenerator cg{};
        Xbyak::Label hook_label{};

        cg.finit();

        // Push args in reverse so st0 = first arg, st7 = last arg.
        for (int i = 7; i >= 0; --i) {
            cg.fld(dword[esp + 4 + i * 4]);
        }

        cg.L(hook_label);
        cg.nop(5, false);
        cg.mov(eax, dword[esp + 36]); // out[] pointer.

        for (int i = 0; i < 8; ++i) {
            cg.fstp(dword[eax + i * 4]);
        }

        cg.ret();

        auto target = cg.getCode<void (*)(float, float, float, float, float, float, float, float, float[])>();
        auto hook_point = const_cast<void*>(reinterpret_cast<const void*>(hook_label.getAddress()));

        static float out[8]{};
        static float captured[8]{};
        static auto get_st = make_get_fpu();
        static auto set_st = make_set_fpu();

        // Unhooked sanity check.
        target(1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f, out);

        for (int i = 0; i < 8; ++i) {
            expect(out[i] == static_cast<float>(i + 1));
        }

        // Read st0..st7.
        struct ReadHook {
            static void fn(SafetyHookContext& ctx) {
                captured[0] = get_st(ctx.st0);
                captured[1] = get_st(ctx.st1);
                captured[2] = get_st(ctx.st2);
                captured[3] = get_st(ctx.st3);
                captured[4] = get_st(ctx.st4);
                captured[5] = get_st(ctx.st5);
                captured[6] = get_st(ctx.st6);
                captured[7] = get_st(ctx.st7);
            }
        };

        static SafetyHookMid read_hook{};

        auto read_result = SafetyHookMid::create(hook_point, ReadHook::fn);

        expect(read_result.has_value());

        read_hook = std::move(*read_result);

        target(10.0f, 20.0f, 30.0f, 40.0f, 50.0f, 60.0f, 70.0f, 80.0f, out);

        for (int i = 0; i < 8; ++i) {
            expect(captured[i] == static_cast<float>((i + 1) * 10));
            expect(out[i] == static_cast<float>((i + 1) * 10));
        }

        read_hook.reset();

        // Write st0..st7.
        struct WriteHook {
            static void fn(SafetyHookContext& ctx) {
                set_st(ctx.st0, 100.0f);
                set_st(ctx.st1, 200.0f);
                set_st(ctx.st2, 300.0f);
                set_st(ctx.st3, 400.0f);
                set_st(ctx.st4, 500.0f);
                set_st(ctx.st5, 600.0f);
                set_st(ctx.st6, 700.0f);
                set_st(ctx.st7, 800.0f);
            }
        };

        static SafetyHookMid write_hook{};

        auto write_result = SafetyHookMid::create(hook_point, WriteHook::fn);

        expect(write_result.has_value());

        write_hook = std::move(*write_result);

        target(1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f, out);

        for (int i = 0; i < 8; ++i) {
            expect(out[i] == static_cast<float>((i + 1) * 100));
        }

        write_hook.reset();

        target(9.0f, 8.0f, 7.0f, 6.0f, 5.0f, 4.0f, 3.0f, 2.0f, out);

        for (int i = 0; i < 8; ++i) {
            expect(out[i] == static_cast<float>(9 - i));
        }
    };

    "Mid hook x87 ST(0..7) (f64)"_test = [] {
        // Load eight doubles onto x87 stack, hook point, then pop them to out[].
        Xbyak::CodeGenerator cg{};
        Xbyak::Label hook_label{};

        cg.finit();

        // Push args in reverse so st0 = first arg, st7 = last arg.
        for (int i = 7; i >= 0; --i) {
            cg.fld(qword[esp + 4 + i * 8]);
        }

        cg.L(hook_label);
        cg.nop(5, false);
        cg.mov(eax, dword[esp + 68]); // out[] pointer.

        for (int i = 0; i < 8; ++i) {
            cg.fstp(qword[eax + i * 8]);
        }

        cg.ret();

        auto target = cg.getCode<void (*)(double, double, double, double, double, double, double, double, double[])>();
        auto hook_point = const_cast<void*>(reinterpret_cast<const void*>(hook_label.getAddress()));

        static double out[8]{};
        static double captured[8]{};
        static auto get_st = make_get_fpu_d();
        static auto set_st = make_set_fpu_d();

        // Unhooked sanity check.
        target(1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, out);

        for (int i = 0; i < 8; ++i) {
            expect(out[i] == static_cast<double>(i + 1));
        }

        // Read st0..st7.
        struct ReadHook {
            static void fn(SafetyHookContext& ctx) {
                captured[0] = get_st(ctx.st0);
                captured[1] = get_st(ctx.st1);
                captured[2] = get_st(ctx.st2);
                captured[3] = get_st(ctx.st3);
                captured[4] = get_st(ctx.st4);
                captured[5] = get_st(ctx.st5);
                captured[6] = get_st(ctx.st6);
                captured[7] = get_st(ctx.st7);
            }
        };

        static SafetyHookMid read_hook{};

        auto read_result = SafetyHookMid::create(hook_point, ReadHook::fn);

        expect(read_result.has_value());

        read_hook = std::move(*read_result);

        target(10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0, out);

        for (int i = 0; i < 8; ++i) {
            expect(captured[i] == static_cast<double>((i + 1) * 10));
            expect(out[i] == static_cast<double>((i + 1) * 10));
        }

        read_hook.reset();

        // Write st0..st7.
        struct WriteHook {
            static void fn(SafetyHookContext& ctx) {
                set_st(ctx.st0, 100.0);
                set_st(ctx.st1, 200.0);
                set_st(ctx.st2, 300.0);
                set_st(ctx.st3, 400.0);
                set_st(ctx.st4, 500.0);
                set_st(ctx.st5, 600.0);
                set_st(ctx.st6, 700.0);
                set_st(ctx.st7, 800.0);
            }
        };

        static SafetyHookMid write_hook{};

        auto write_result = SafetyHookMid::create(hook_point, WriteHook::fn);

        expect(write_result.has_value());

        write_hook = std::move(*write_result);

        target(1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, out);

        for (int i = 0; i < 8; ++i) {
            expect(out[i] == static_cast<double>((i + 1) * 100));
        }

        write_hook.reset();

        target(9.0, 8.0, 7.0, 6.0, 5.0, 4.0, 3.0, 2.0, out);

        for (int i = 0; i < 8; ++i) {
            expect(out[i] == static_cast<double>(9 - i));
        }
    };

    "Mid hook MXCSR"_test = [] {
        // Load MXCSR from arg, then return cvtss2si(3.5f).
        // Default round-to-nearest gives 4, round-down gives 3.
        Xbyak::CodeGenerator cg{};
        Xbyak::Label hook_label{}, three_and_half{};

        cg.mov(eax, dword[esp + 4]); // Arg: uint32_t mxcsr value.
        cg.push(eax);
        cg.ldmxcsr(dword[esp]);
        cg.add(esp, 4);
        cg.L(hook_label);
        cg.nop(5, false);
        cg.movss(xmm0, dword[three_and_half]);
        cg.cvtss2si(eax, xmm0);
        cg.ret();
        cg.L(three_and_half);
        cg.db(0x00);
        cg.db(0x00);
        cg.db(0x60);
        cg.db(0x40); // 3.5f

        auto target = cg.getCode<uint32_t (*)(uint32_t)>();
        auto hook_point = const_cast<void*>(reinterpret_cast<const void*>(hook_label.getAddress()));

        static uint32_t captured{};

        constexpr uint32_t round_down = 0x3F80;

        expect(target(0x1F80u) == 4_u);
        expect(target(round_down) == 3_u);

        struct ReadHook {
            static void fn(SafetyHookContext& ctx) { captured = ctx.mxcsr; }
        };

        static SafetyHookMid read_hook{};

        auto read_result = SafetyHookMid::create(hook_point, ReadHook::fn);

        expect(read_result.has_value());

        read_hook = std::move(*read_result);

        target(round_down);

        expect(captured == round_down);

        read_hook.reset();

        struct WriteHook {
            static void fn(SafetyHookContext& ctx) { ctx.mxcsr = round_down; }
        };

        static SafetyHookMid write_hook{};

        auto write_result = SafetyHookMid::create(hook_point, WriteHook::fn);

        expect(write_result.has_value());

        write_hook = std::move(*write_result);

        expect(target(0x1F80u) == 3_u);

        write_hook.reset();

        expect(target(0x1F80u) == 4_u);
    };
#endif

    "Mid hook enable and disable"_test = [] {
        struct Target {
            SAFETYHOOK_NOINLINE static int SAFETYHOOK_FASTCALL add_42(int a) {
                volatile int b = a;
                return b + 42;
            }
        };

        expect(Target::add_42(0) == 42_i);
        expect(Target::add_42(1) == 43_i);
        expect(Target::add_42(2) == 44_i);

        static SafetyHookMid hook;

        struct Hook {
            static void add_42(SafetyHookContext& ctx) {
#if SAFETYHOOK_OS_WINDOWS
#if SAFETYHOOK_ARCH_X86_64
                ctx.rcx = 1337 - 42;
#elif SAFETYHOOK_ARCH_X86_32
                ctx.ecx = 1337 - 42;
#endif
#elif SAFETYHOOK_OS_LINUX
#if SAFETYHOOK_ARCH_X86_64
                ctx.rdi = 1337 - 42;
#elif SAFETYHOOK_ARCH_X86_32
                ctx.edi = 1337 - 42;
#endif
#endif
            }
        };

        auto hook_result = SafetyHookMid::create(Target::add_42, Hook::add_42, SafetyHookMid::StartDisabled);

        expect(hook_result.has_value());

        hook = std::move(*hook_result);

        expect(Target::add_42(0) == 42_i);
        expect(Target::add_42(1) == 43_i);
        expect(Target::add_42(2) == 44_i);

        expect(hook.enable().has_value());

        expect(Target::add_42(1) == 1337_i);
        expect(Target::add_42(2) == 1337_i);
        expect(Target::add_42(3) == 1337_i);

        expect(hook.disable().has_value());

        expect(Target::add_42(0) == 42_i);
        expect(Target::add_42(1) == 43_i);
        expect(Target::add_42(2) == 44_i);

        hook.reset();

        expect(Target::add_42(0) == 42_i);
        expect(Target::add_42(1) == 43_i);
        expect(Target::add_42(2) == 44_i);
    };
};