#include <xbyak/xbyak.h>

#include <boost/ut.hpp>
#include <safetyhook.hpp>

using namespace boost::ut;
using namespace Xbyak::util;

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

        // Unhooked sanity check.
        target(1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f, out);

        for (int i = 0; i < 8; ++i) {
            expect(out[i] == static_cast<float>(i + 1));
        }

        // Read st0..st7.
        struct ReadHook {
            static void fn(SafetyHookContext& ctx) {
                captured[0] = ctx.st0.as_f32();
                captured[1] = ctx.st1.as_f32();
                captured[2] = ctx.st2.as_f32();
                captured[3] = ctx.st3.as_f32();
                captured[4] = ctx.st4.as_f32();
                captured[5] = ctx.st5.as_f32();
                captured[6] = ctx.st6.as_f32();
                captured[7] = ctx.st7.as_f32();
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
                ctx.st0.set_f32(100.0f);
                ctx.st1.set_f32(200.0f);
                ctx.st2.set_f32(300.0f);
                ctx.st3.set_f32(400.0f);
                ctx.st4.set_f32(500.0f);
                ctx.st5.set_f32(600.0f);
                ctx.st6.set_f32(700.0f);
                ctx.st7.set_f32(800.0f);
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

        // Unhooked sanity check.
        target(1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, out);

        for (int i = 0; i < 8; ++i) {
            expect(out[i] == static_cast<double>(i + 1));
        }

        // Read st0..st7.
        struct ReadHook {
            static void fn(SafetyHookContext& ctx) {
                captured[0] = ctx.st0.as_f64();
                captured[1] = ctx.st1.as_f64();
                captured[2] = ctx.st2.as_f64();
                captured[3] = ctx.st3.as_f64();
                captured[4] = ctx.st4.as_f64();
                captured[5] = ctx.st5.as_f64();
                captured[6] = ctx.st6.as_f64();
                captured[7] = ctx.st7.as_f64();
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
                ctx.st0.set_f64(100.0);
                ctx.st1.set_f64(200.0);
                ctx.st2.set_f64(300.0);
                ctx.st3.set_f64(400.0);
                ctx.st4.set_f64(500.0);
                ctx.st5.set_f64(600.0);
                ctx.st6.set_f64(700.0);
                ctx.st7.set_f64(800.0);
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