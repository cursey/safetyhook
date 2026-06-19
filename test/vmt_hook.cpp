#include <gtest/gtest.h>
#include <safetyhook.hpp>

#include "vmt_targets.hpp"

using namespace safetyhook::test;

#if SAFETYHOOK_ABI_MSVC
static constexpr auto VMT_OFFSET = 0;
#elif SAFETYHOOK_ABI_ITANIUM
static constexpr auto VMT_OFFSET = 1;
#endif

TEST(VmtHook, VMTHookAnObjectInstance) {
    auto target = make_single_target();

    EXPECT_EQ(target->add_42(0), 42);

    SafetyHookVmt target_hook{};
    static SafetyHookVm* add_42_hook{};
    SafetyHookVm add_42_hook_storage{};
    add_42_hook = &add_42_hook_storage;

    struct Hook : SingleTarget {
        int hooked_add_42(int a) { return add_42_hook->thiscall<int>(this, a) + 1337; }
    };

    auto vmt_result = SafetyHookVmt::create(target.get());

    ASSERT_TRUE(vmt_result.has_value());

    target_hook = std::move(*vmt_result);

    auto vm_result = target_hook.hook_method(1 + VMT_OFFSET, &Hook::hooked_add_42);

    ASSERT_TRUE(vm_result.has_value());

    add_42_hook_storage = std::move(*vm_result);

    EXPECT_EQ(target->add_42(1), 1380);

    add_42_hook_storage.reset();

    EXPECT_EQ(target->add_42(2), 44);

    target_hook.reset();
}

TEST(VmtHook, ResettingTheVMTHookRemovesAllVMHooksForThatObject) {
    auto target = make_dual_target();

    EXPECT_EQ(target->add_42(0), 42);
    EXPECT_EQ(target->add_43(0), 43);

    SafetyHookVmt target_hook{};
    static SafetyHookVm* add_42_hook{};
    static SafetyHookVm* add_43_hook{};
    SafetyHookVm add_42_hook_storage{};
    SafetyHookVm add_43_hook_storage{};
    add_42_hook = &add_42_hook_storage;
    add_43_hook = &add_43_hook_storage;

    struct Hook : DualTarget {
        int hooked_add_42(int a) { return add_42_hook->thiscall<int>(this, a) + 1337; }
        int hooked_add_43(int a) { return add_43_hook->thiscall<int>(this, a) + 1337; }
    };

    auto vmt_result = SafetyHookVmt::create(target.get());

    ASSERT_TRUE(vmt_result.has_value());

    target_hook = std::move(*vmt_result);

    auto vm_result = target_hook.hook_method(1 + VMT_OFFSET, &Hook::hooked_add_42);

    ASSERT_TRUE(vm_result.has_value());

    add_42_hook_storage = std::move(*vm_result);

    EXPECT_EQ(target->add_42(1), 1380);

    vm_result = target_hook.hook_method(2 + VMT_OFFSET, &Hook::hooked_add_43);

    ASSERT_TRUE(vm_result.has_value());

    add_43_hook_storage = std::move(*vm_result);

    EXPECT_EQ(target->add_43(1), 1381);

    target_hook.reset();

    EXPECT_EQ(target->add_42(2), 44);
    EXPECT_EQ(target->add_43(2), 45);

    add_42_hook_storage.reset();
    add_43_hook_storage.reset();
}

TEST(VmtHook, VMTHookingAnObjectMaintainsCorrectRTTI) {
    auto target = make_single_target();

    EXPECT_EQ(target->add_42(0), 42);
    EXPECT_NE(dynamic_cast<SingleInterface*>(target.get()), nullptr);

    SafetyHookVmt target_hook{};
    static SafetyHookVm* add_42_hook{};
    SafetyHookVm add_42_hook_storage{};
    add_42_hook = &add_42_hook_storage;

    struct Hook : SingleTarget {
        int hooked_add_42(int a) { return add_42_hook->thiscall<int>(this, a) + 1337; }
    };

    auto vmt_result = SafetyHookVmt::create(target.get());

    ASSERT_TRUE(vmt_result.has_value());

    target_hook = std::move(*vmt_result);

    auto vm_result = target_hook.hook_method(1 + VMT_OFFSET, &Hook::hooked_add_42);

    ASSERT_TRUE(vm_result.has_value());

    add_42_hook_storage = std::move(*vm_result);

    EXPECT_EQ(target->add_42(1), 1380);
    EXPECT_NE(dynamic_cast<SingleInterface*>(target.get()), nullptr);

    add_42_hook_storage.reset();
    target_hook.reset();
}

TEST(VmtHook, CanSafelyDestroyVmtHookAfterObjectIsDeleted) {
    auto target = make_single_target();

    EXPECT_EQ(target->add_42(0), 42);

    SafetyHookVmt target_hook{};
    static SafetyHookVm* add_42_hook{};
    SafetyHookVm add_42_hook_storage{};
    add_42_hook = &add_42_hook_storage;

    struct Hook : SingleTarget {
        int hooked_add_42(int a) { return add_42_hook->thiscall<int>(this, a) + 1337; }
    };

    auto vmt_result = SafetyHookVmt::create(target.get());

    ASSERT_TRUE(vmt_result.has_value());

    target_hook = std::move(*vmt_result);

    auto vm_result = target_hook.hook_method(1 + VMT_OFFSET, &Hook::hooked_add_42);

    ASSERT_TRUE(vm_result.has_value());

    add_42_hook_storage = std::move(*vm_result);

    EXPECT_EQ(target->add_42(1), 1380);

    target.reset();
    target_hook.reset();
    add_42_hook_storage.reset();
}

TEST(VmtHook, CanApplyAnExistingVMTHookToMoreThanOneObject) {
    auto target = make_single_target();
    auto target0 = make_single_target();
    auto target1 = make_single_target();
    auto target2 = make_single_target();

    EXPECT_EQ(target->add_42(0), 42);

    SafetyHookVmt target_hook{};
    static SafetyHookVm* add_42_hook{};
    SafetyHookVm add_42_hook_storage{};
    add_42_hook = &add_42_hook_storage;

    struct Hook : SingleTarget {
        int hooked_add_42(int a) { return add_42_hook->thiscall<int>(this, a) + 1337; }
    };

    auto vmt_result = SafetyHookVmt::create(target.get());

    ASSERT_TRUE(vmt_result.has_value());

    target_hook = std::move(*vmt_result);

    auto vm_result = target_hook.hook_method(1 + VMT_OFFSET, &Hook::hooked_add_42);

    ASSERT_TRUE(vm_result.has_value());

    add_42_hook_storage = std::move(*vm_result);

    target_hook.apply(target0.get());
    target_hook.apply(target1.get());
    target_hook.apply(target2.get());

    EXPECT_EQ(target->add_42(1), 1380);
    EXPECT_EQ(target0->add_42(1), 1380);
    EXPECT_EQ(target1->add_42(1), 1380);
    EXPECT_EQ(target2->add_42(1), 1380);

    add_42_hook_storage.reset();

    EXPECT_EQ(target->add_42(2), 44);
    EXPECT_EQ(target0->add_42(2), 44);
    EXPECT_EQ(target1->add_42(2), 44);
    EXPECT_EQ(target2->add_42(2), 44);

    target_hook.reset();
}

TEST(VmtHook, CanRemoveAnObjectThatWasPreviouslyVMTHooked) {
    auto target = make_single_target();
    auto target0 = make_single_target();
    auto target1 = make_single_target();
    auto target2 = make_single_target();

    EXPECT_EQ(target->add_42(0), 42);

    SafetyHookVmt target_hook{};
    static SafetyHookVm* add_42_hook{};
    SafetyHookVm add_42_hook_storage{};
    add_42_hook = &add_42_hook_storage;

    struct Hook : SingleTarget {
        int hooked_add_42(int a) { return add_42_hook->thiscall<int>(this, a) + 1337; }
    };

    auto vmt_result = SafetyHookVmt::create(target.get());

    ASSERT_TRUE(vmt_result.has_value());

    target_hook = std::move(*vmt_result);

    auto vm_result = target_hook.hook_method(1 + VMT_OFFSET, &Hook::hooked_add_42);

    ASSERT_TRUE(vm_result.has_value());

    add_42_hook_storage = std::move(*vm_result);

    target_hook.apply(target0.get());
    target_hook.apply(target1.get());
    target_hook.apply(target2.get());

    EXPECT_EQ(target->add_42(1), 1380);
    EXPECT_EQ(target0->add_42(1), 1380);
    EXPECT_EQ(target1->add_42(1), 1380);
    EXPECT_EQ(target2->add_42(1), 1380);

    target_hook.remove(target0.get());

    EXPECT_EQ(target->add_42(2), 1381);
    EXPECT_EQ(target0->add_42(2), 44);
    EXPECT_EQ(target1->add_42(2), 1381);
    EXPECT_EQ(target2->add_42(2), 1381);

    target_hook.remove(target2.get());

    EXPECT_EQ(target->add_42(2), 1381);
    EXPECT_EQ(target0->add_42(2), 44);
    EXPECT_EQ(target1->add_42(2), 1381);
    EXPECT_EQ(target2->add_42(2), 44);

    target_hook.remove(target.get());

    EXPECT_EQ(target->add_42(2), 44);
    EXPECT_EQ(target0->add_42(2), 44);
    EXPECT_EQ(target1->add_42(2), 1381);
    EXPECT_EQ(target2->add_42(2), 44);

    target_hook.remove(target1.get());

    EXPECT_EQ(target->add_42(2), 44);
    EXPECT_EQ(target0->add_42(2), 44);
    EXPECT_EQ(target1->add_42(2), 44);
    EXPECT_EQ(target2->add_42(2), 44);

    add_42_hook_storage.reset();
    target_hook.reset();
}

TEST(VmtHook, VMTHookAnObjectInstanceWithEasyAPI) {
    auto target = make_single_target();

    EXPECT_EQ(target->add_42(0), 42);

    SafetyHookVmt target_hook{};
    static SafetyHookVm* add_42_hook{};
    SafetyHookVm add_42_hook_storage{};
    add_42_hook = &add_42_hook_storage;

    struct Hook : SingleTarget {
        int hooked_add_42(int a) { return add_42_hook->thiscall<int>(this, a) + 1337; }
    };

    target_hook = safetyhook::create_vmt(target.get());
    add_42_hook_storage = safetyhook::create_vm(target_hook, 1 + VMT_OFFSET, &Hook::hooked_add_42);

    EXPECT_EQ(target->add_42(1), 1380);

    add_42_hook_storage.reset();

    EXPECT_EQ(target->add_42(2), 44);

    target_hook.reset();
}

TEST(VmtHook, VMTHookPreservesDynamicCastWithCrossCast) {
    auto target = make_cast_target();

    CastBase2* base2 = target.get();

    SafetyHookVmt base2_hook{};
    static SafetyHookVm* add_1337_hook{};
    SafetyHookVm add_1337_hook_storage{};
    add_1337_hook = &add_1337_hook_storage;

    struct Hook : CastTarget {
        int hooked_add_1337(int a) { return add_1337_hook->thiscall<int>(this, a) + 42; }
    };

    auto vmt_result = SafetyHookVmt::create(base2);
    ASSERT_TRUE(vmt_result.has_value());
    base2_hook = std::move(*vmt_result);

    auto vm_result = base2_hook.hook_method(1 + VMT_OFFSET, &Hook::hooked_add_1337);
    ASSERT_TRUE(vm_result.has_value());
    add_1337_hook_storage = std::move(*vm_result);

    EXPECT_EQ(base2->add_1337(1), 1380);

    // Cross-cast: CastBase2* -> CastBase1*
    // Runtime reads offset-to-top from CastBase2's vptr[-2]
    // Without the fix this is garbage and will crash or return wrong pointer
    CastBase1* base1 = dynamic_cast<CastBase1*>(base2);
    EXPECT_NE(base1, nullptr);
    EXPECT_EQ(base1->add_42(1), 43);

    add_1337_hook_storage.reset();
    base2_hook.reset();
}
