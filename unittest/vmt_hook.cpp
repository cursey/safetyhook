#include <catch2/catch_test_macros.hpp>
#include <safetyhook.hpp>

TEST_CASE("VMT hook an object instance", "[vmt_hook]") {
    struct Target {
        __declspec(noinline) virtual int add_42(int a) {
            return a + 42;
        }
    };

    Target target{};

    REQUIRE(target.add_42(0) == 42);

    static SafetyHookVmt vmt;
    static SafetyHookVm hook;

    struct Hook {
        static int __thiscall add_42(Target* self, int a) {
            return hook.thiscall<int>(self, a) + 1337;
        }
    };

    auto vmt_result = SafetyHookVmt::create(&target);

    REQUIRE(vmt_result);

    vmt = std::move(*vmt_result);

    auto hook_result = vmt.hook(0, Hook::add_42);

    REQUIRE(hook_result);

    hook = std::move(*hook_result);

    REQUIRE(target.add_42(1) == 1380);
}