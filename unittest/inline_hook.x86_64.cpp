#if defined(_M_X64)

#include <catch2/catch_test_macros.hpp>
#include <xbyak/xbyak.h>
#include <safetyhook.hpp>

void asciiz(Xbyak::CodeGenerator& cg, const char* str) {
    while (*str) {
        cg.db(*str++);
    }

    cg.db(0);
}

TEST_CASE("Function with RIP-relative operand is hooked", "[inline-hook-x86_64]") {
    using namespace std::literals;
    using namespace Xbyak::util;

    Xbyak::CodeGenerator cg{};
    Xbyak::Label str_label{};

    cg.lea(rax, ptr [rip + str_label]);
    cg.ret();

    for (auto i = 0; i < 10; ++i) {
        cg.nop(10, false);
    }

    cg.L(str_label);
    asciiz(cg, "Hello");

    const auto fn = cg.getCode<const char*(*)()>();

    REQUIRE((fn() == "Hello"sv));

    static SafetyHookInline hook;

    struct Hook {
        static const char* fn() { return "Hello, world!"; }
    };

    auto hook_result = SafetyHookInline::create(reinterpret_cast<void*>(fn), reinterpret_cast<void*>(Hook::fn));

    REQUIRE(hook_result);

    hook = std::move(*hook_result);

    REQUIRE((fn() == "Hello, world!"sv));

    hook.reset();

    REQUIRE((fn() == "Hello"sv));
}

TEST_CASE("Function with no nearby memory is hooked", "[inline-hook-x86_64]") {
    using namespace Xbyak::util;

    Xbyak::CodeGenerator cg{5'000'000'000}; // 5 GB
    Xbyak::Label start{};

    cg.nop(2'500'000'000, false); // 2.5 GB
    cg.L(start);
    cg.mov(dword[rsp + 8], ecx);
    cg.mov(eax, dword[rsp + 8]);
    cg.imul(eax, dword[rsp + 8]);
    cg.ret();

    auto fn = reinterpret_cast<int (*)(int)>(const_cast<uint8_t*>(start.getAddress()));

    REQUIRE(fn(2) == 4);
    REQUIRE(fn(3) == 9);
    REQUIRE(fn(4) == 16);

    static SafetyHookInline hook;

    struct Hook {
        static int fn(int a) { return hook.call<int>(a) * a; }
    };

    auto hook_result = SafetyHookInline::create(reinterpret_cast<void*>(fn), reinterpret_cast<void*>(Hook::fn));

    REQUIRE(hook_result);

    hook = std::move(*hook_result);

    REQUIRE(fn(2) == 8);
    REQUIRE(fn(3) == 27);
    REQUIRE(fn(4) == 64);

    hook.reset();

    REQUIRE(fn(2) == 4);
    REQUIRE(fn(3) == 9);
    REQUIRE(fn(4) == 16);
}

#endif