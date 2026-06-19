#include <gtest/gtest.h>
#include <safetyhook.hpp>

TEST(MidHook, MidHookToChangeARegister) {
    struct Target {
        SAFETYHOOK_NOINLINE static int SAFETYHOOK_FASTCALL add_42(int a) { return a + 42; }
    };

    using Add42Fn = int(SAFETYHOOK_FASTCALL*)(int);
    // Force a real indirect call so MinGW Release cannot optimize around runtime patching.
    Add42Fn volatile add_42 = Target::add_42;

    EXPECT_EQ(add_42(0), 42);

    SafetyHookMid hook;

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
            *reinterpret_cast<int*>(ctx.esp + 4) = 1337 - 42;
#endif
#endif
        }
    };

    auto hook_result = SafetyHookMid::create(Target::add_42, Hook::add_42);

    ASSERT_TRUE(hook_result.has_value());

    hook = std::move(*hook_result);

    EXPECT_EQ(add_42(1), 1337);

    hook.reset();

    EXPECT_EQ(add_42(2), 44);
}

#if SAFETYHOOK_ARCH_X86_64
TEST(MidHook, MidHookToChangeAnXMMRegister) {
    struct Target {
        SAFETYHOOK_NOINLINE static float SAFETYHOOK_FASTCALL add_42(float a) { return a + 0.42f; }
    };

    using Add42Fn = float(SAFETYHOOK_FASTCALL*)(float);
    // Force a real indirect call so MinGW Release cannot optimize around runtime patching.
    Add42Fn volatile add_42 = Target::add_42;

    EXPECT_FLOAT_EQ(add_42(0.0f), 0.42f);

    SafetyHookMid hook;

    struct Hook {
        static void add_42(SafetyHookContext& ctx) { ctx.xmm0.f32[0] = 1337.0f - 0.42f; }
    };

    auto hook_result = SafetyHookMid::create(Target::add_42, Hook::add_42);

    ASSERT_TRUE(hook_result.has_value());

    hook = std::move(*hook_result);

    EXPECT_FLOAT_EQ(add_42(1.0f), 1337.0f);

    hook.reset();

    EXPECT_FLOAT_EQ(add_42(2.0f), 2.42f);
}
#endif

TEST(MidHook, MidHookEnableAndDisable) {
    struct Target {
        SAFETYHOOK_NOINLINE static int SAFETYHOOK_FASTCALL add_42(int a) {
            volatile int b = a;
            return b + 42;
        }
    };

    using Add42Fn = int(SAFETYHOOK_FASTCALL*)(int);
    // Force a real indirect call so MinGW Release cannot optimize around runtime patching.
    Add42Fn volatile add_42 = Target::add_42;

    EXPECT_EQ(add_42(0), 42);
    EXPECT_EQ(add_42(1), 43);
    EXPECT_EQ(add_42(2), 44);

    SafetyHookMid hook;

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
            *reinterpret_cast<int*>(ctx.esp + 4) = 1337 - 42;
#endif
#endif
        }
    };

    auto hook_result = SafetyHookMid::create(Target::add_42, Hook::add_42, SafetyHookMid::StartDisabled);

    ASSERT_TRUE(hook_result.has_value());

    hook = std::move(*hook_result);

    EXPECT_EQ(add_42(0), 42);
    EXPECT_EQ(add_42(1), 43);
    EXPECT_EQ(add_42(2), 44);

    ASSERT_TRUE(hook.enable().has_value());

    EXPECT_EQ(add_42(1), 1337);
    EXPECT_EQ(add_42(2), 1337);
    EXPECT_EQ(add_42(3), 1337);

    ASSERT_TRUE(hook.disable().has_value());

    EXPECT_EQ(add_42(0), 42);
    EXPECT_EQ(add_42(1), 43);
    EXPECT_EQ(add_42(2), 44);

    hook.reset();

    EXPECT_EQ(add_42(0), 42);
    EXPECT_EQ(add_42(1), 43);
    EXPECT_EQ(add_42(2), 44);
}
