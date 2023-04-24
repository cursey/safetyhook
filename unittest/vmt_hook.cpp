#include <catch2/catch_test_macros.hpp>
#include <safetyhook.hpp>

TEST_CASE("VMT hook an object instance", "[vmt_hook]") {
    struct Interface {
        virtual ~Interface() = default;
        virtual int add_42(int a) = 0;
    };

    struct Target : Interface {
        __declspec(noinline) int add_42(int a) override { return a + 42; }
    };

    std::unique_ptr<Interface> target = std::make_unique<Target>();

    REQUIRE(target->add_42(0) == 42);

    static SafetyHookVmt target_hook{};
    static SafetyHookVm add_42_hook{};

    struct Hook : Target {
        int hooked_add_42(int a) { return add_42_hook.thiscall<int>(this, a) + 1337; }
    };

    auto vmt_result = SafetyHookVmt::create(target.get());

    REQUIRE(vmt_result);

    target_hook = std::move(*vmt_result);

    auto vm_result = target_hook.hook_method(1, &Hook::hooked_add_42);

    REQUIRE(vm_result);

    add_42_hook = std::move(*vm_result);

    REQUIRE(target->add_42(1) == 1380);

    add_42_hook.reset();

    REQUIRE(target->add_42(2) == 44);
}

TEST_CASE("Resetting the VMT hook removes all VM hooks for that object", "[vmt_hook]") {
    struct Interface {
        virtual ~Interface() = default;
        virtual int add_42(int a) = 0;
        virtual int add_43(int a) = 0;
    };

    struct Target : Interface {
        __declspec(noinline) int add_42(int a) override { return a + 42; }
        __declspec(noinline) int add_43(int a) override { return a + 43; }
    };

    std::unique_ptr<Interface> target = std::make_unique<Target>();

    REQUIRE(target->add_42(0) == 42);
    REQUIRE(target->add_43(0) == 43);

    static SafetyHookVmt target_hook{};
    static SafetyHookVm add_42_hook{};
    static SafetyHookVm add_43_hook{};

    struct Hook : Target {
        int hooked_add_42(int a) { return add_42_hook.thiscall<int>(this, a) + 1337; }
        int hooked_add_43(int a) { return add_43_hook.thiscall<int>(this, a) + 1337; }
    };

    auto vmt_result = SafetyHookVmt::create(target.get());

    REQUIRE(vmt_result);

    target_hook = std::move(*vmt_result);

    auto vm_result = target_hook.hook_method(1, &Hook::hooked_add_42);

    REQUIRE(vm_result);

    add_42_hook = std::move(*vm_result);

    REQUIRE(target->add_42(1) == 1380);

    vm_result = target_hook.hook_method(2, &Hook::hooked_add_43);

    REQUIRE(vm_result);

    add_43_hook = std::move(*vm_result);

    REQUIRE(target->add_43(1) == 1381);

    target_hook.reset();

    REQUIRE(target->add_42(2) == 44);
    REQUIRE(target->add_43(2) == 45);
}

TEST_CASE("VMT hooking an object maintains correct RTTI", "[vmt_hook]") {
    struct Interface {
        virtual ~Interface() = default;
        virtual int add_42(int a) = 0;
    };

    struct Target : Interface {
        __declspec(noinline) int add_42(int a) override { return a + 42; }
    };

    std::unique_ptr<Interface> target = std::make_unique<Target>();

    REQUIRE(target->add_42(0) == 42);
    REQUIRE(dynamic_cast<Target*>(target.get()) != nullptr);

    static SafetyHookVmt target_hook{};
    static SafetyHookVm add_42_hook{};

    struct Hook : Target {
        int hooked_add_42(int a) { return add_42_hook.thiscall<int>(this, a) + 1337; }
    };

    auto vmt_result = SafetyHookVmt::create(target.get());

    REQUIRE(vmt_result);

    target_hook = std::move(*vmt_result);

    auto vm_result = target_hook.hook_method(1, &Hook::hooked_add_42);

    REQUIRE(vm_result);

    add_42_hook = std::move(*vm_result);

    REQUIRE(target->add_42(1) == 1380);
    REQUIRE(dynamic_cast<Target*>(target.get()) != nullptr);
}