#include <catch2/catch_test_macros.hpp>
#include <safetyhook.hpp>

TEST_CASE("Mid hook to change a register", "[mid_hook]") {
    struct Target {
        __declspec(noinline) static int __fastcall add_42(int a) { return a + 42; }
    };

    REQUIRE(Target::add_42(0) == 42);

    static SafetyHookMid hook;

    struct Hook {
        static void add_42(SafetyHookContext& ctx) {
#if defined(_M_X64)
            ctx.rcx = 1337 - 42;
#elif defined(_M_IX86)
            ctx.ecx = 1337 - 42;
#else
#error "Unsupported architecture"
#endif
        }
    };

    auto hook_result = SafetyHookMid::create(Target::add_42, Hook::add_42);

    REQUIRE(hook_result);

    hook = std::move(*hook_result);

    REQUIRE(Target::add_42(1) == 1337);

    hook.reset();

    REQUIRE(Target::add_42(2) == 44);
}

#ifdef _M_X64
TEST_CASE("Mid hook to change an XMM register", "[mid_hook]") {
    struct Target {
        __declspec(noinline) static float __fastcall add_42(float a) { return a + 0.42f; }
    };

    REQUIRE(Target::add_42(0.0f) == 0.42f);

    static SafetyHookMid hook;

    struct Hook {
        static void add_42(SafetyHookContext& ctx) { ctx.xmm0.f32[0] = 1337.0f - 0.42f; }
    };

    auto hook_result = SafetyHookMid::create(Target::add_42, Hook::add_42);

    REQUIRE(hook_result);

    hook = std::move(*hook_result);

    REQUIRE(Target::add_42(1.0f) == 1337.0f);

    hook.reset();

    REQUIRE(Target::add_42(2.0f) == 2.42f);
}
#endif