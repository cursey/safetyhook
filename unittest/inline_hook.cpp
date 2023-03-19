#include <catch2/catch_test_macros.hpp>
#include <xbyak/xbyak.h>
#include <safetyhook.hpp>

TEST_CASE("Function hooked multiple times", "[inline_hook]") {
    struct Target {
        __declspec(noinline) static std::string fn(std::string name) { return "hello " + name; }
    };

    REQUIRE(Target::fn("world") == "hello world");

    // First hook.
    static SafetyHookInline hook0;

    struct Hook0 {
        static std::string fn(std::string name) { return hook0.call<std::string>(name + " and bob"); }
    };

    auto hook0_result = SafetyHookInline::create(reinterpret_cast<void*>(Target::fn), reinterpret_cast<void*>(Hook0::fn));

    REQUIRE(hook0_result);

    hook0 = std::move(*hook0_result);

    REQUIRE(Target::fn("world") == "hello world and bob");

    // Second hook.
    static SafetyHookInline hook1;

    struct Hook1 {
        static std::string fn(std::string name) { return hook1.call<std::string>(name + " and alice"); }
    };

    auto hook1_result = SafetyHookInline::create(reinterpret_cast<void*>(Target::fn), reinterpret_cast<void*>(Hook1::fn));

    REQUIRE(hook1_result);

    hook1 = std::move(*hook1_result);

    REQUIRE(Target::fn("world") == "hello world and alice and bob");

    // Third hook.
    static SafetyHookInline hook2;

    struct Hook2 {
        static std::string fn(std::string name) { return hook2.call<std::string>(name + " and eve"); }
    };

    auto hook2_result = SafetyHookInline::create(reinterpret_cast<void*>(Target::fn), reinterpret_cast<void*>(Hook2::fn));

    REQUIRE(hook2_result);

    hook2 = std::move(*hook2_result);

    REQUIRE(Target::fn("world") == "hello world and eve and alice and bob");

    // Fourth hook.
    static SafetyHookInline hook3;

    struct Hook3 {
        static std::string fn(std::string name) { return hook3.call<std::string>(name + " and carol"); }
    };

    auto hook3_result = SafetyHookInline::create(reinterpret_cast<void*>(Target::fn), reinterpret_cast<void*>(Hook3::fn));

    REQUIRE(hook3_result);

    hook3 = std::move(*hook3_result);

    REQUIRE(Target::fn("world") == "hello world and carol and eve and alice and bob");

    // Unhook.
    hook3.reset();
    hook2.reset();
    hook1.reset();
    hook0.reset();
}

TEST_CASE("Function with multiple args hooked", "[inline_hook]") {
    struct Target {
        __declspec(noinline) static int add(int x, int y) { return x + y; }
    };

    REQUIRE(Target::add(2, 3) == 5);

    static SafetyHookInline add_hook;

    struct AddHook {
        static int add(int x, int y) { return add_hook.call<int>(x * 2, y * 2); }
    };

    auto add_hook_result = SafetyHookInline::create(reinterpret_cast<void*>(Target::add), reinterpret_cast<void*>(AddHook::add));

    REQUIRE(add_hook_result);

    add_hook = std::move(*add_hook_result);

    REQUIRE(Target::add(3, 4) == 14);

    add_hook.reset();

    REQUIRE(Target::add(5, 6) == 11);
}

TEST_CASE("Active function is hooked and unhooked", "[inline_hook]") {
    using namespace std::literals;

    static int count = 0;
    static bool is_running = true;

    struct Target {
        __declspec(noinline) static std::string say_hello(int times) { return "Hello #" + std::to_string(times); }

        static void say_hello_infinitely() {
            while (is_running) {
                say_hello(count++);
            }
        }
    };

    std::thread t{Target::say_hello_infinitely};

    std::this_thread::sleep_for(1s);

    static SafetyHookInline hook;

    struct Hook {
        static std::string say_hello(int times [[maybe_unused]]) { return hook.call<std::string>(1337); }
    };

    auto hook_result = SafetyHookInline::create(reinterpret_cast<void*>(Target::say_hello), reinterpret_cast<void*>(Hook::say_hello));

    REQUIRE(hook_result);

    hook = std::move(*hook_result);

    REQUIRE(Target::say_hello(0) == "Hello #1337");

    std::this_thread::sleep_for(1s);
    hook.reset();

    is_running = false;
    t.join();

    REQUIRE(Target::say_hello(0) == "Hello #0");
    REQUIRE(count > 0);
}

TEST_CASE("Function with short unconditional branch is hooked", "[inline-hook]") {
    using namespace std::literals;
    using namespace Xbyak::util;

    static SafetyHookInline hook;

    struct Hook {
        static int __fastcall fn() { 
            return hook.fastcall<int>() + 42; 
        };
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

    const auto fn = cg.getCode<int(__fastcall*)()>();

    REQUIRE(fn() == 1);

    hook = safetyhook::create_inline(reinterpret_cast<void*>(fn), reinterpret_cast<void*>(Hook::fn));

    REQUIRE(fn() == 43);

    hook.reset();

    REQUIRE(fn() == 1);
}

TEST_CASE("Function with short conditional branch is hooked", "[inline-hook]") {
    using namespace std::literals;
    using namespace Xbyak::util;

    static SafetyHookInline hook;

    struct Hook {
        static int __fastcall fn(int x) { 
            return hook.fastcall<int>(x) + 42; 
        };
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
        return cg.getCode<int(__fastcall*)(int)>();
    };

    cg.cmp(ecx, 8);

    SECTION("JB") {
        cg.jb(label);
        const auto fn = finalize();

        CHECK(fn(7) == 1);
        CHECK(fn(8) == 0);
        CHECK(fn(9) == 0);

        hook = safetyhook::create_inline(reinterpret_cast<void*>(fn), reinterpret_cast<void*>(Hook::fn));

        CHECK(fn(7) == 43);
        CHECK(fn(8) == 42);
        CHECK(fn(9) == 42);

        hook.reset();

        CHECK(fn(7) == 1);
        CHECK(fn(8) == 0);
        CHECK(fn(9) == 0);
    }

    SECTION("JBE") {
        cg.jbe(label);
        const auto fn = finalize();

        CHECK(fn(7) == 1);
        CHECK(fn(8) == 1);
        CHECK(fn(9) == 0);

        hook = safetyhook::create_inline(reinterpret_cast<void*>(fn), reinterpret_cast<void*>(Hook::fn));

        CHECK(fn(7) == 43);
        CHECK(fn(8) == 43);
        CHECK(fn(9) == 42);

        hook.reset();

        CHECK(fn(7) == 1);
        CHECK(fn(8) == 1);
        CHECK(fn(9) == 0);
    }

    SECTION("JL") {
        cg.jl(label);
        const auto fn = finalize();

        CHECK(fn(7) == 1);
        CHECK(fn(8) == 0);
        CHECK(fn(9) == 0);

        hook = safetyhook::create_inline(reinterpret_cast<void*>(fn), reinterpret_cast<void*>(Hook::fn));

        CHECK(fn(7) == 43);
        CHECK(fn(8) == 42);
        CHECK(fn(9) == 42);

        hook.reset();

        CHECK(fn(7) == 1);
        CHECK(fn(8) == 0);
        CHECK(fn(9) == 0);
    }

    SECTION("JLE") {
        cg.jle(label);
        const auto fn = finalize();

        CHECK(fn(7) == 1);
        CHECK(fn(8) == 1);
        CHECK(fn(9) == 0);

        hook = safetyhook::create_inline(reinterpret_cast<void*>(fn), reinterpret_cast<void*>(Hook::fn));

        CHECK(fn(7) == 43);
        CHECK(fn(8) == 43);
        CHECK(fn(9) == 42);

        hook.reset();

        CHECK(fn(7) == 1);
        CHECK(fn(8) == 1);
        CHECK(fn(9) == 0);
    }

    SECTION("JNB") {
        cg.jnb(label);
        const auto fn = finalize();

        CHECK(fn(7) == 0);
        CHECK(fn(8) == 1);
        CHECK(fn(9) == 1);

        hook = safetyhook::create_inline(reinterpret_cast<void*>(fn), reinterpret_cast<void*>(Hook::fn));

        CHECK(fn(7) == 42);
        CHECK(fn(8) == 43);
        CHECK(fn(9) == 43);

        hook.reset();

        CHECK(fn(7) == 0);
        CHECK(fn(8) == 1);
        CHECK(fn(9) == 1);
    }

    SECTION("JNBE") {
        cg.jnbe(label);
        const auto fn = finalize();

        CHECK(fn(7) == 0);
        CHECK(fn(8) == 0);
        CHECK(fn(9) == 1);

        hook = safetyhook::create_inline(reinterpret_cast<void*>(fn), reinterpret_cast<void*>(Hook::fn));

        CHECK(fn(7) == 42);
        CHECK(fn(8) == 42);
        CHECK(fn(9) == 43);

        hook.reset();

        CHECK(fn(7) == 0);
        CHECK(fn(8) == 0);
        CHECK(fn(9) == 1);
    }

    SECTION("JNL") {
        cg.jnl(label);
        const auto fn = finalize();

        CHECK(fn(7) == 0);
        CHECK(fn(8) == 1);
        CHECK(fn(9) == 1);

        hook = safetyhook::create_inline(reinterpret_cast<void*>(fn), reinterpret_cast<void*>(Hook::fn));

        CHECK(fn(7) == 42);
        CHECK(fn(8) == 43);
        CHECK(fn(9) == 43);

        hook.reset();

        CHECK(fn(7) == 0);
        CHECK(fn(8) == 1);
        CHECK(fn(9) == 1);
    }

    SECTION("JNLE") {
        cg.jnle(label);
        const auto fn = finalize();

        CHECK(fn(7) == 0);
        CHECK(fn(8) == 0);
        CHECK(fn(9) == 1);

        hook = safetyhook::create_inline(reinterpret_cast<void*>(fn), reinterpret_cast<void*>(Hook::fn));

        CHECK(fn(7) == 42);
        CHECK(fn(8) == 42);
        CHECK(fn(9) == 43);

        hook.reset();

        CHECK(fn(7) == 0);
        CHECK(fn(8) == 0);
        CHECK(fn(9) == 1);
    }

    SECTION("JNO") {
        cg.jno(label);
        const auto fn = finalize();

        CHECK(fn(7) == 1);
        CHECK(fn(8) == 1);
        CHECK(fn(9) == 1);

        hook = safetyhook::create_inline(reinterpret_cast<void*>(fn), reinterpret_cast<void*>(Hook::fn));

        CHECK(fn(7) == 43);
        CHECK(fn(8) == 43);
        CHECK(fn(9) == 43);

        hook.reset();

        CHECK(fn(7) == 1);
        CHECK(fn(8) == 1);
        CHECK(fn(9) == 1);
    }

    SECTION("JNP") {
        cg.jnp(label);
        const auto fn = finalize();

        CHECK(fn(7) == 0);
        CHECK(fn(8) == 0);
        CHECK(fn(9) == 1);

        hook = safetyhook::create_inline(reinterpret_cast<void*>(fn), reinterpret_cast<void*>(Hook::fn));

        CHECK(fn(7) == 42);
        CHECK(fn(8) == 42);
        CHECK(fn(9) == 43);

        hook.reset();

        CHECK(fn(7) == 0);
        CHECK(fn(8) == 0);
        CHECK(fn(9) == 1);
    }

    SECTION("JNS") {
        cg.jns(label);
        const auto fn = finalize();

        CHECK(fn(7) == 0);
        CHECK(fn(8) == 1);
        CHECK(fn(9) == 1);

        hook = safetyhook::create_inline(reinterpret_cast<void*>(fn), reinterpret_cast<void*>(Hook::fn));

        CHECK(fn(7) == 42);
        CHECK(fn(8) == 43);
        CHECK(fn(9) == 43);

        hook.reset();

        CHECK(fn(7) == 0);
        CHECK(fn(8) == 1);
        CHECK(fn(9) == 1);
    }

    SECTION("JNZ") {
        cg.jnz(label);
        const auto fn = finalize();

        CHECK(fn(7) == 1);
        CHECK(fn(8) == 0);
        CHECK(fn(9) == 1);

        hook = safetyhook::create_inline(reinterpret_cast<void*>(fn), reinterpret_cast<void*>(Hook::fn));

        CHECK(fn(7) == 43);
        CHECK(fn(8) == 42);
        CHECK(fn(9) == 43);

        hook.reset();

        CHECK(fn(7) == 1);
        CHECK(fn(8) == 0);
        CHECK(fn(9) == 1);
    }

    SECTION("JO") {
        cg.jo(label);
        const auto fn = finalize();

        CHECK(fn(7) == 0);
        CHECK(fn(8) == 0);
        CHECK(fn(9) == 0);

        hook = safetyhook::create_inline(reinterpret_cast<void*>(fn), reinterpret_cast<void*>(Hook::fn));

        CHECK(fn(7) == 42);
        CHECK(fn(8) == 42);
        CHECK(fn(9) == 42);

        hook.reset();

        CHECK(fn(7) == 0);
        CHECK(fn(8) == 0);
        CHECK(fn(9) == 0);
    }

    SECTION("JP") {
        cg.jp(label);
        const auto fn = finalize();

        CHECK(fn(7) == 1);
        CHECK(fn(8) == 1);
        CHECK(fn(9) == 0);

        hook = safetyhook::create_inline(reinterpret_cast<void*>(fn), reinterpret_cast<void*>(Hook::fn));

        CHECK(fn(7) == 43);
        CHECK(fn(8) == 43);
        CHECK(fn(9) == 42);

        hook.reset();

        CHECK(fn(7) == 1);
        CHECK(fn(8) == 1);
        CHECK(fn(9) == 0);
    }

    SECTION("JS") {
        cg.js(label);
        const auto fn = finalize();

        CHECK(fn(7) == 1);
        CHECK(fn(8) == 0);
        CHECK(fn(9) == 0);

        hook = safetyhook::create_inline(reinterpret_cast<void*>(fn), reinterpret_cast<void*>(Hook::fn));

        CHECK(fn(7) == 43);
        CHECK(fn(8) == 42);
        CHECK(fn(9) == 42);

        hook.reset();

        CHECK(fn(7) == 1);
        CHECK(fn(8) == 0);
        CHECK(fn(9) == 0);
    }

    SECTION("JZ") {
        cg.jz(label);
        const auto fn = finalize();

        CHECK(fn(7) == 0);
        CHECK(fn(8) == 1);
        CHECK(fn(9) == 0);

        hook = safetyhook::create_inline(reinterpret_cast<void*>(fn), reinterpret_cast<void*>(Hook::fn));

        CHECK(fn(7) == 42);
        CHECK(fn(8) == 43);
        CHECK(fn(9) == 42);

        hook.reset();

        CHECK(fn(7) == 0);
        CHECK(fn(8) == 1);
        CHECK(fn(9) == 0);
    }
}

TEST_CASE("Function with short jump inside trampoline", "[inline-hook]") {
    using namespace Xbyak::util;

    Xbyak::CodeGenerator cg{};

    cg.jmp("@f");
    cg.ret();
    cg.L("@@");
    cg.mov(eax, 42);
    cg.ret();
    cg.nop(10, false);
    
    const auto fn = cg.getCode<int(*)()>();

    REQUIRE(fn() == 42);

    static SafetyHookInline hook;

    struct Hook {
        static int fn() {
            return hook.call<int>() + 1;
        }
    };

    hook = safetyhook::create_inline(reinterpret_cast<void*>(fn), reinterpret_cast<void*>(Hook::fn));

    REQUIRE(fn() == 43);

    hook.reset();

    REQUIRE(fn() == 42);
}