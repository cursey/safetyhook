#include <atomic>
#include <chrono>
#include <string>
#include <string_view>
#include <thread>

#include <gtest/gtest.h>
#include <safetyhook.hpp>
#include <xbyak/xbyak.h>

using namespace std::literals;
using namespace Xbyak::util;

TEST(InlineHook, FunctionHookedMultipleTimes) {
    struct Target {
        SAFETYHOOK_NOINLINE static std::string fn(std::string name) { return "hello " + name; }
    };

    EXPECT_EQ(Target::fn("world"), "hello world"sv);

    // First hook.
    static SafetyHookInline* hook0_ptr{};
    SafetyHookInline hook0;
    hook0_ptr = &hook0;

    struct Hook0 {
        static std::string fn(std::string name) { return hook0_ptr->call<std::string>(name + " and bob"); }
    };

    auto hook0_result = SafetyHookInline::create(Target::fn, Hook0::fn);

    ASSERT_TRUE(hook0_result.has_value());

    hook0 = std::move(*hook0_result);

    EXPECT_EQ(Target::fn("world"), "hello world and bob"sv);

    // Second hook.
    static SafetyHookInline* hook1_ptr{};
    SafetyHookInline hook1;
    hook1_ptr = &hook1;

    struct Hook1 {
        static std::string fn(std::string name) { return hook1_ptr->call<std::string>(name + " and alice"); }
    };

    auto hook1_result = SafetyHookInline::create(Target::fn, Hook1::fn);

    ASSERT_TRUE(hook1_result.has_value());

    hook1 = std::move(*hook1_result);

    EXPECT_EQ(Target::fn("world"), "hello world and alice and bob"sv);

    // Third hook.
    static SafetyHookInline* hook2_ptr{};
    SafetyHookInline hook2;
    hook2_ptr = &hook2;

    struct Hook2 {
        static std::string fn(std::string name) { return hook2_ptr->call<std::string>(name + " and eve"); }
    };

    auto hook2_result = SafetyHookInline::create(Target::fn, Hook2::fn);

    ASSERT_TRUE(hook2_result.has_value());

    hook2 = std::move(*hook2_result);

    EXPECT_EQ(Target::fn("world"), "hello world and eve and alice and bob"sv);

    // Fourth hook.
    static SafetyHookInline* hook3_ptr{};
    SafetyHookInline hook3;
    hook3_ptr = &hook3;

    struct Hook3 {
        static std::string fn(std::string name) { return hook3_ptr->call<std::string>(name + " and carol"); }
    };

    auto hook3_result = SafetyHookInline::create(Target::fn, Hook3::fn);

    ASSERT_TRUE(hook3_result.has_value());

    hook3 = std::move(*hook3_result);

    EXPECT_EQ(Target::fn("world"), "hello world and carol and eve and alice and bob"sv);

    // Unhook.
    hook3.reset();
    hook2.reset();
    hook1.reset();
    hook0.reset();
}

TEST(InlineHook, FunctionWithMultipleArgsHooked) {
    struct Target {
        SAFETYHOOK_NOINLINE static int add(int x, int y) { return x + y; }
    };

    using AddFn = int (*)(int, int);
    // Force a real indirect call so MinGW Release cannot optimize around runtime patching.
    AddFn volatile add = Target::add;

    EXPECT_EQ(add(2, 3), 5);

    static SafetyHookInline* add_hook_ptr{};
    SafetyHookInline add_hook;
    add_hook_ptr = &add_hook;

    struct AddHook {
        static int add(int x, int y) { return add_hook_ptr->call<int>(x * 2, y * 2); }
    };

    auto add_hook_result = SafetyHookInline::create(Target::add, AddHook::add);

    ASSERT_TRUE(add_hook_result.has_value());

    add_hook = std::move(*add_hook_result);

    EXPECT_EQ(add(3, 4), 14);

    add_hook.reset();

    EXPECT_EQ(add(5, 6), 11);
}

#if SAFETYHOOK_OS_WINDOWS
TEST(InlineHook, ActiveFunctionIsHookedAndUnhooked) {
    static std::atomic<int> count = 0;
    static std::atomic<bool> is_running = true;
    static std::atomic<bool> pause_worker = false;
    static std::atomic<bool> worker_paused = false;

    count.store(0, std::memory_order_relaxed);
    is_running.store(true, std::memory_order_relaxed);
    pause_worker.store(false, std::memory_order_relaxed);
    worker_paused.store(false, std::memory_order_relaxed);

    struct Target {
        SAFETYHOOK_NOINLINE static std::string say_hello(int times) { return "Hello #" + std::to_string(times); }

        static void say_hello_infinitely() {
            while (is_running.load(std::memory_order_relaxed)) {
                if (pause_worker.load(std::memory_order_acquire)) {
                    worker_paused.store(true, std::memory_order_release);
                    while (pause_worker.load(std::memory_order_acquire) && is_running.load(std::memory_order_relaxed)) {
                        std::this_thread::yield();
                    }
                    worker_paused.store(false, std::memory_order_release);
                    continue;
                }

                say_hello(count.fetch_add(1, std::memory_order_relaxed));
            }
        }
    };

    std::thread t{Target::say_hello_infinitely};

    std::this_thread::sleep_for(1s);

    // This test hooks code in the same image as safetyhook, which makes trap_threads keep the page executable.
    // Pause the worker while patching so the test does not race instruction writes. Hooking other images does not
    // need this manual synchronization because thread trapping redirects execution during the patch window.
    pause_worker.store(true, std::memory_order_release);

    while (!worker_paused.load(std::memory_order_acquire)) {
        std::this_thread::yield();
    }

    static SafetyHookInline* hook_ptr{};
    SafetyHookInline hook;
    hook_ptr = &hook;

    struct Hook {
        static std::string say_hello(int times [[maybe_unused]]) { return hook_ptr->call<std::string>(1337); }
    };

    const auto stop_worker = [&] {
        is_running.store(false, std::memory_order_relaxed);
        pause_worker.store(false, std::memory_order_release);
        if (t.joinable()) {
            t.join();
        }
    };

    auto hook_result = SafetyHookInline::create(Target::say_hello, Hook::say_hello, SafetyHookInline::StartDisabled);

    if (!hook_result.has_value()) {
        stop_worker();
        FAIL() << "Failed to create inline hook.";
    }

    hook = std::move(*hook_result);

    if (!hook.enable().has_value()) {
        stop_worker();
        FAIL() << "Failed to enable inline hook.";
    }
    pause_worker.store(false, std::memory_order_release);

    EXPECT_EQ(Target::say_hello(0), "Hello #1337"sv);

    std::this_thread::sleep_for(1s);

    pause_worker.store(true, std::memory_order_release);

    while (!worker_paused.load(std::memory_order_acquire)) {
        std::this_thread::yield();
    }

    hook.reset();

    stop_worker();

    EXPECT_EQ(Target::say_hello(0), "Hello #0"sv);
    EXPECT_GT(count.load(std::memory_order_relaxed), 0);
}
#endif

TEST(InlineHook, FunctionWithShortUnconditionalBranchIsHooked) {
    static SafetyHookInline* hook_ptr{};
    SafetyHookInline hook;
    hook_ptr = &hook;

    struct Hook {
        static int SAFETYHOOK_FASTCALL fn() { return hook_ptr->fastcall<int>() + 42; };
    };

    Xbyak::CodeGenerator cg{};

    cg.jmp("@f");
    cg.mov(eax, 0);
    cg.ret();
    cg.nop(10, false);
    cg.L("@@");
    cg.mov(eax, 1);
    cg.ret();
    cg.nop(10, false);

    const auto fn = cg.getCode<int(SAFETYHOOK_FASTCALL*)()>();

    EXPECT_EQ(fn(), 1);

    hook = safetyhook::create_inline(fn, Hook::fn);

    EXPECT_EQ(fn(), 43);

    hook.reset();

    EXPECT_EQ(fn(), 1);
}

TEST(InlineHook, FunctionWithShortConditionalBranchIsHooked) {
    static SafetyHookInline* hook_ptr{};
    SafetyHookInline hook;
    hook_ptr = &hook;

    struct Hook {
        static int SAFETYHOOK_FASTCALL fn(int x) { return hook_ptr->fastcall<int>(x) + 42; };
    };

    Xbyak::CodeGenerator cg{};
    Xbyak::Label label{};
    const auto finalize = [&cg, &label] {
        cg.mov(eax, 0);
        cg.ret();
        cg.nop(10, false);
        cg.L(label);
        cg.mov(eax, 1);
        cg.ret();
        cg.nop(10, false);
        return cg.getCode<int(SAFETYHOOK_FASTCALL*)(int)>();
    };

#if SAFETYHOOK_OS_WINDOWS
    constexpr auto param = ecx;
#elif SAFETYHOOK_OS_LINUX
#if SAFETYHOOK_ARCH_X86_64
    constexpr auto param = edi;
#elif SAFETYHOOK_ARCH_X86_32
    auto param = dword[esp + 4];
#endif
#endif

    SCOPED_TRACE("JB");
    {
        cg.cmp(param, 8);
        cg.jb(label);
        const auto fn = finalize();

        EXPECT_EQ(fn(7), 1);
        EXPECT_EQ(fn(8), 0);
        EXPECT_EQ(fn(9), 0);

        hook = safetyhook::create_inline(fn, Hook::fn);

        EXPECT_EQ(fn(7), 43);
        EXPECT_EQ(fn(8), 42);
        EXPECT_EQ(fn(9), 42);

        hook.reset();

        EXPECT_EQ(fn(7), 1);
        EXPECT_EQ(fn(8), 0);
        EXPECT_EQ(fn(9), 0);

        cg.reset();
    }

    SCOPED_TRACE("JBE");
    {
        cg.cmp(param, 8);
        cg.jbe(label);
        const auto fn = finalize();

        EXPECT_EQ(fn(7), 1);
        EXPECT_EQ(fn(8), 1);
        EXPECT_EQ(fn(9), 0);

        hook = safetyhook::create_inline(fn, Hook::fn);

        EXPECT_EQ(fn(7), 43);
        EXPECT_EQ(fn(8), 43);
        EXPECT_EQ(fn(9), 42);

        hook.reset();

        EXPECT_EQ(fn(7), 1);
        EXPECT_EQ(fn(8), 1);
        EXPECT_EQ(fn(9), 0);

        cg.reset();
    }

    SCOPED_TRACE("JL");
    {
        cg.cmp(param, 8);
        cg.jl(label);
        const auto fn = finalize();

        EXPECT_EQ(fn(7), 1);
        EXPECT_EQ(fn(8), 0);
        EXPECT_EQ(fn(9), 0);

        hook = safetyhook::create_inline(fn, Hook::fn);

        EXPECT_EQ(fn(7), 43);
        EXPECT_EQ(fn(8), 42);
        EXPECT_EQ(fn(9), 42);

        hook.reset();

        EXPECT_EQ(fn(7), 1);
        EXPECT_EQ(fn(8), 0);
        EXPECT_EQ(fn(9), 0);

        cg.reset();
    }

    SCOPED_TRACE("JLE");
    {
        cg.cmp(param, 8);
        cg.jle(label);
        const auto fn = finalize();

        EXPECT_EQ(fn(7), 1);
        EXPECT_EQ(fn(8), 1);
        EXPECT_EQ(fn(9), 0);

        hook = safetyhook::create_inline(fn, Hook::fn);

        EXPECT_EQ(fn(7), 43);
        EXPECT_EQ(fn(8), 43);
        EXPECT_EQ(fn(9), 42);

        hook.reset();

        EXPECT_EQ(fn(7), 1);
        EXPECT_EQ(fn(8), 1);
        EXPECT_EQ(fn(9), 0);

        cg.reset();
    }

    SCOPED_TRACE("JNB");
    {
        cg.cmp(param, 8);
        cg.jnb(label);
        const auto fn = finalize();

        EXPECT_EQ(fn(7), 0);
        EXPECT_EQ(fn(8), 1);
        EXPECT_EQ(fn(9), 1);

        hook = safetyhook::create_inline(fn, Hook::fn);

        EXPECT_EQ(fn(7), 42);
        EXPECT_EQ(fn(8), 43);
        EXPECT_EQ(fn(9), 43);

        hook.reset();

        EXPECT_EQ(fn(7), 0);
        EXPECT_EQ(fn(8), 1);
        EXPECT_EQ(fn(9), 1);

        cg.reset();
    }

    SCOPED_TRACE("JNBE");
    {
        cg.cmp(param, 8);
        cg.jnbe(label);
        const auto fn = finalize();

        EXPECT_EQ(fn(7), 0);
        EXPECT_EQ(fn(8), 0);
        EXPECT_EQ(fn(9), 1);

        hook = safetyhook::create_inline(fn, Hook::fn);

        EXPECT_EQ(fn(7), 42);
        EXPECT_EQ(fn(8), 42);
        EXPECT_EQ(fn(9), 43);

        hook.reset();

        EXPECT_EQ(fn(7), 0);
        EXPECT_EQ(fn(8), 0);
        EXPECT_EQ(fn(9), 1);

        cg.reset();
    }

    SCOPED_TRACE("JNL");
    {
        cg.cmp(param, 8);
        cg.jnl(label);
        const auto fn = finalize();

        EXPECT_EQ(fn(7), 0);
        EXPECT_EQ(fn(8), 1);
        EXPECT_EQ(fn(9), 1);

        hook = safetyhook::create_inline(fn, Hook::fn);

        EXPECT_EQ(fn(7), 42);
        EXPECT_EQ(fn(8), 43);
        EXPECT_EQ(fn(9), 43);

        hook.reset();

        EXPECT_EQ(fn(7), 0);
        EXPECT_EQ(fn(8), 1);
        EXPECT_EQ(fn(9), 1);

        cg.reset();
    }

    SCOPED_TRACE("JNLE");
    {
        cg.cmp(param, 8);
        cg.jnle(label);
        const auto fn = finalize();

        EXPECT_EQ(fn(7), 0);
        EXPECT_EQ(fn(8), 0);
        EXPECT_EQ(fn(9), 1);

        hook = safetyhook::create_inline(fn, Hook::fn);

        EXPECT_EQ(fn(7), 42);
        EXPECT_EQ(fn(8), 42);
        EXPECT_EQ(fn(9), 43);

        hook.reset();

        EXPECT_EQ(fn(7), 0);
        EXPECT_EQ(fn(8), 0);
        EXPECT_EQ(fn(9), 1);

        cg.reset();
    }

    SCOPED_TRACE("JNO");
    {
        cg.cmp(param, 8);
        cg.jno(label);
        const auto fn = finalize();

        EXPECT_EQ(fn(7), 1);
        EXPECT_EQ(fn(8), 1);
        EXPECT_EQ(fn(9), 1);

        hook = safetyhook::create_inline(fn, Hook::fn);

        EXPECT_EQ(fn(7), 43);
        EXPECT_EQ(fn(8), 43);
        EXPECT_EQ(fn(9), 43);

        hook.reset();

        EXPECT_EQ(fn(7), 1);
        EXPECT_EQ(fn(8), 1);
        EXPECT_EQ(fn(9), 1);

        cg.reset();
    }

    SCOPED_TRACE("JNP");
    {
        cg.cmp(param, 8);
        cg.jnp(label);
        const auto fn = finalize();

        EXPECT_EQ(fn(7), 0);
        EXPECT_EQ(fn(8), 0);
        EXPECT_EQ(fn(9), 1);

        hook = safetyhook::create_inline(fn, Hook::fn);

        EXPECT_EQ(fn(7), 42);
        EXPECT_EQ(fn(8), 42);
        EXPECT_EQ(fn(9), 43);

        hook.reset();

        EXPECT_EQ(fn(7), 0);
        EXPECT_EQ(fn(8), 0);
        EXPECT_EQ(fn(9), 1);

        cg.reset();
    }

    SCOPED_TRACE("JNS");
    {
        cg.cmp(param, 8);
        cg.jns(label);
        const auto fn = finalize();

        EXPECT_EQ(fn(7), 0);
        EXPECT_EQ(fn(8), 1);
        EXPECT_EQ(fn(9), 1);

        hook = safetyhook::create_inline(fn, Hook::fn);

        EXPECT_EQ(fn(7), 42);
        EXPECT_EQ(fn(8), 43);
        EXPECT_EQ(fn(9), 43);

        hook.reset();

        EXPECT_EQ(fn(7), 0);
        EXPECT_EQ(fn(8), 1);
        EXPECT_EQ(fn(9), 1);

        cg.reset();
    }

    SCOPED_TRACE("JNZ");
    {
        cg.cmp(param, 8);
        cg.jnz(label);
        const auto fn = finalize();

        EXPECT_EQ(fn(7), 1);
        EXPECT_EQ(fn(8), 0);
        EXPECT_EQ(fn(9), 1);

        hook = safetyhook::create_inline(fn, Hook::fn);

        EXPECT_EQ(fn(7), 43);
        EXPECT_EQ(fn(8), 42);
        EXPECT_EQ(fn(9), 43);

        hook.reset();

        EXPECT_EQ(fn(7), 1);
        EXPECT_EQ(fn(8), 0);
        EXPECT_EQ(fn(9), 1);

        cg.reset();
    }

    SCOPED_TRACE("JO");
    {
        cg.cmp(param, 8);
        cg.jo(label);
        const auto fn = finalize();

        EXPECT_EQ(fn(7), 0);
        EXPECT_EQ(fn(8), 0);
        EXPECT_EQ(fn(9), 0);

        hook = safetyhook::create_inline(fn, Hook::fn);

        EXPECT_EQ(fn(7), 42);
        EXPECT_EQ(fn(8), 42);
        EXPECT_EQ(fn(9), 42);

        hook.reset();

        EXPECT_EQ(fn(7), 0);
        EXPECT_EQ(fn(8), 0);
        EXPECT_EQ(fn(9), 0);

        cg.reset();
    }

    SCOPED_TRACE("JP");
    {
        cg.cmp(param, 8);
        cg.jp(label);
        const auto fn = finalize();

        EXPECT_EQ(fn(7), 1);
        EXPECT_EQ(fn(8), 1);
        EXPECT_EQ(fn(9), 0);

        hook = safetyhook::create_inline(fn, Hook::fn);

        EXPECT_EQ(fn(7), 43);
        EXPECT_EQ(fn(8), 43);
        EXPECT_EQ(fn(9), 42);

        hook.reset();

        EXPECT_EQ(fn(7), 1);
        EXPECT_EQ(fn(8), 1);
        EXPECT_EQ(fn(9), 0);

        cg.reset();
    }

    SCOPED_TRACE("JS");
    {
        cg.cmp(param, 8);
        cg.js(label);
        const auto fn = finalize();

        EXPECT_EQ(fn(7), 1);
        EXPECT_EQ(fn(8), 0);
        EXPECT_EQ(fn(9), 0);

        hook = safetyhook::create_inline(fn, Hook::fn);

        EXPECT_EQ(fn(7), 43);
        EXPECT_EQ(fn(8), 42);
        EXPECT_EQ(fn(9), 42);

        hook.reset();

        EXPECT_EQ(fn(7), 1);
        EXPECT_EQ(fn(8), 0);
        EXPECT_EQ(fn(9), 0);

        cg.reset();
    }

    SCOPED_TRACE("JZ");
    {
        cg.cmp(param, 8);
        cg.jz(label);
        const auto fn = finalize();

        EXPECT_EQ(fn(7), 0);
        EXPECT_EQ(fn(8), 1);
        EXPECT_EQ(fn(9), 0);

        hook = safetyhook::create_inline(fn, Hook::fn);

        EXPECT_EQ(fn(7), 42);
        EXPECT_EQ(fn(8), 43);
        EXPECT_EQ(fn(9), 42);

        hook.reset();

        EXPECT_EQ(fn(7), 0);
        EXPECT_EQ(fn(8), 1);
        EXPECT_EQ(fn(9), 0);

        cg.reset();
    }
}

TEST(InlineHook, FunctionWithShortJumpInsideTrampoline) {
    Xbyak::CodeGenerator cg{};

    cg.jmp("@f");
    cg.ret();
    cg.L("@@");
    cg.mov(eax, 42);
    cg.ret();
    cg.nop(10, false);

    const auto fn = cg.getCode<int (*)()>();

    EXPECT_EQ(fn(), 42);

    static SafetyHookInline* hook_ptr{};
    SafetyHookInline hook;
    hook_ptr = &hook;

    struct Hook {
        static int fn() { return hook_ptr->call<int>() + 1; }
    };

    hook = safetyhook::create_inline(fn, Hook::fn);

    EXPECT_EQ(fn(), 43);

    hook.reset();

    EXPECT_EQ(fn(), 42);
}

TEST(InlineHook, FunctionHookCanBeEnableAndDisabled) {
    struct Target {
        SAFETYHOOK_NOINLINE static int fn(int a) {
            volatile int b = a;
            return b * 2;
        }
    };

    using Fn = int (*)(int);
    // Force a real indirect call so MinGW Release cannot optimize around runtime patching.
    Fn volatile fn = Target::fn;

    EXPECT_EQ(fn(1), 2);
    EXPECT_EQ(fn(2), 4);
    EXPECT_EQ(fn(3), 6);

    static SafetyHookInline* hook_ptr{};
    SafetyHookInline hook;
    hook_ptr = &hook;

    struct Hook {
        static int fn(int a) { return hook_ptr->call<int>(a + 1); }
    };

    auto hook0_result = SafetyHookInline::create(Target::fn, Hook::fn, SafetyHookInline::StartDisabled);

    ASSERT_TRUE(hook0_result.has_value());

    hook = std::move(*hook0_result);

    EXPECT_EQ(fn(1), 2);
    EXPECT_EQ(fn(2), 4);
    EXPECT_EQ(fn(3), 6);

    ASSERT_TRUE(hook.enable().has_value());

    EXPECT_EQ(fn(1), 4);
    EXPECT_EQ(fn(2), 6);
    EXPECT_EQ(fn(3), 8);

    ASSERT_TRUE(hook.disable().has_value());

    EXPECT_EQ(fn(1), 2);
    EXPECT_EQ(fn(2), 4);
    EXPECT_EQ(fn(3), 6);

    hook.reset();

    EXPECT_EQ(fn(1), 2);
    EXPECT_EQ(fn(2), 4);
    EXPECT_EQ(fn(3), 6);
}
