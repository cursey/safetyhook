#include <cstdint>
#include <string_view>

#include <gtest/gtest.h>
#include <safetyhook.hpp>
#include <xbyak/xbyak.h>

#if SAFETYHOOK_ARCH_X86_64

using namespace std::literals;
using namespace Xbyak::util;

void asciiz(Xbyak::CodeGenerator& cg, const char* str) {
    while (*str) {
        cg.db(*str++);
    }

    cg.db(0);
}

TEST(InlineHookX64, FunctionWithRIPRelativeOperandIsHooked) {
    Xbyak::CodeGenerator cg{};
    Xbyak::Label str_label{};

    cg.lea(rax, ptr[rip + str_label]);
    cg.ret();

    for (auto i = 0; i < 10; ++i) {
        cg.nop(10, false);
    }

    cg.L(str_label);
    asciiz(cg, "Hello");

    const auto fn = cg.getCode<const char* (*)()>();

    EXPECT_EQ(fn(), "Hello"sv);

    SafetyHookInline hook;

    struct Hook {
        static const char* fn() { return "Hello, world!"; }
    };

    auto hook_result = SafetyHookInline::create(fn, Hook::fn);

    ASSERT_TRUE(hook_result.has_value());

    hook = std::move(*hook_result);

    EXPECT_EQ(fn(), "Hello, world!"sv);

    hook.reset();

    EXPECT_EQ(fn(), "Hello"sv);
}

TEST(InlineHookX64, FunctionWithNoNearbyMemoryIsHooked) {
    Xbyak::CodeGenerator cg{5'000'000'000}; // 5 GB
    Xbyak::Label start{};

    cg.nop(2'500'000'000, false); // 2.5 GB
    cg.L(start);

#if SAFETYHOOK_OS_WINDOWS
    cg.mov(dword[rsp + 8], ecx);
    cg.mov(eax, dword[rsp + 8]);
    cg.imul(eax, dword[rsp + 8]);
#elif SAFETYHOOK_OS_LINUX
    cg.mov(eax, edi);
    cg.imul(eax, edi);
#endif

    cg.ret();

    auto fn = reinterpret_cast<int (*)(int)>(const_cast<uint8_t*>(start.getAddress()));

    EXPECT_EQ(fn(2), 4);
    EXPECT_EQ(fn(3), 9);
    EXPECT_EQ(fn(4), 16);

    static SafetyHookInline* hook_ptr{};
    SafetyHookInline hook;
    hook_ptr = &hook;

    struct Hook {
        static int fn(int a) { return hook_ptr->call<int>(a) * a; }
    };

    auto hook_result = SafetyHookInline::create(fn, Hook::fn);

    ASSERT_TRUE(hook_result.has_value());

    hook = std::move(*hook_result);

    EXPECT_EQ(fn(2), 8);
    EXPECT_EQ(fn(3), 27);
    EXPECT_EQ(fn(4), 64);

    hook.reset();

    EXPECT_EQ(fn(2), 4);
    EXPECT_EQ(fn(3), 9);
    EXPECT_EQ(fn(4), 16);
}

TEST(InlineHookX64, StackedHooksOnFarFunctionRemovedFromMiddle) {
    Xbyak::CodeGenerator cg{5'000'000'000}; // 5 GB
    Xbyak::Label start{};

    cg.nop(2'500'000'000, false); // 2.5 GB so the target is out of e9 range and uses the FF trampoline.
    cg.L(start);

#if SAFETYHOOK_OS_WINDOWS
    cg.mov(dword[rsp + 8], ecx);
    cg.mov(eax, dword[rsp + 8]);
    cg.imul(eax, dword[rsp + 8]);
#elif SAFETYHOOK_OS_LINUX
    cg.mov(eax, edi);
    cg.imul(eax, edi);
#endif

    cg.ret();

    auto fn = reinterpret_cast<int (*)(int)>(const_cast<uint8_t*>(start.getAddress()));

    EXPECT_EQ(fn(3), 9);

    static SafetyHookInline* bottom_ptr{};
    static SafetyHookInline* middle_ptr{};
    static SafetyHookInline* top_ptr{};

    SafetyHookInline bottom;
    SafetyHookInline middle;
    SafetyHookInline top;
    bottom_ptr = &bottom;
    middle_ptr = &middle;
    top_ptr = &top;

    struct Hooks {
        static int bottom(int a) { return bottom_ptr->call<int>(a) + 1; }
        static int middle(int a) { return middle_ptr->call<int>(a) + 10; }
        static int top(int a) { return top_ptr->call<int>(a) + 100; }
    };

    bottom = safetyhook::create_inline(fn, Hooks::bottom);
    middle = safetyhook::create_inline(fn, Hooks::middle);
    top = safetyhook::create_inline(fn, Hooks::top);

    EXPECT_EQ(fn(3), 9 + 111);

    // Remove the middle hook of the FF-trampoline chain; the rest must re-chain through fresh trampolines.
    middle.reset();

    for (int i = 0; i < 16; ++i) {
        EXPECT_EQ(fn(3), 9 + 101);
    }

    top.reset();
    EXPECT_EQ(fn(3), 9 + 1);

    bottom.reset();
    EXPECT_EQ(fn(3), 9);
}

#endif
