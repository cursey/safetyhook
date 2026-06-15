#include <boost/ut.hpp>
#include <safetyhook.hpp>

using namespace boost::ut;

#if SAFETYHOOK_ABI_MSVC
static constexpr auto VMT_OFFSET = 0;
#elif SAFETYHOOK_ABI_ITANIUM
static constexpr auto VMT_OFFSET = 1;
#endif

static suite<"vmt hook"> vmt_hook_tests = [] {
    "VMT hook an object instance"_test = [] {
        struct Interface {
            virtual ~Interface() = default;
            virtual int add_42(int a) = 0;
        };

        struct Target : Interface {
            SAFETYHOOK_NOINLINE int add_42(int a) override { return a + 42; }
        };

        std::unique_ptr<Interface> target = std::make_unique<Target>();

        expect(target->add_42(0) == 42_i);

        static SafetyHookVmt target_hook{};
        static SafetyHookVm add_42_hook{};

        struct Hook : Target {
            int hooked_add_42(int a) { return add_42_hook.thiscall<int>(this, a) + 1337; }
        };

        auto vmt_result = SafetyHookVmt::create(target.get());

        expect(vmt_result.has_value());

        target_hook = std::move(*vmt_result);

        auto vm_result = target_hook.hook_method(1 + VMT_OFFSET, &Hook::hooked_add_42);

        expect(vm_result.has_value());

        add_42_hook = std::move(*vm_result);

        expect(target->add_42(1) == 1380_i);

        add_42_hook.reset();

        expect(target->add_42(2) == 44_i);
    };

    "Resetting the VMT hook removes all VM hooks for that object"_test = [] {
        struct Interface {
            virtual ~Interface() = default;
            virtual int add_42(int a) = 0;
            virtual int add_43(int a) = 0;
        };

        struct Target : Interface {
            SAFETYHOOK_NOINLINE int add_42(int a) override { return a + 42; }
            SAFETYHOOK_NOINLINE int add_43(int a) override { return a + 43; }
        };

        std::unique_ptr<Interface> target = std::make_unique<Target>();

        expect(target->add_42(0) == 42_i);
        expect(target->add_43(0) == 43_i);

        static SafetyHookVmt target_hook{};
        static SafetyHookVm add_42_hook{};
        static SafetyHookVm add_43_hook{};

        struct Hook : Target {
            int hooked_add_42(int a) { return add_42_hook.thiscall<int>(this, a) + 1337; }
            int hooked_add_43(int a) { return add_43_hook.thiscall<int>(this, a) + 1337; }
        };

        auto vmt_result = SafetyHookVmt::create(target.get());

        expect(vmt_result.has_value());

        target_hook = std::move(*vmt_result);

        auto vm_result = target_hook.hook_method(1 + VMT_OFFSET, &Hook::hooked_add_42);

        expect(vm_result.has_value());

        add_42_hook = std::move(*vm_result);

        expect(target->add_42(1) == 1380_i);

        vm_result = target_hook.hook_method(2 + VMT_OFFSET, &Hook::hooked_add_43);

        expect(vm_result.has_value());

        add_43_hook = std::move(*vm_result);

        expect(target->add_43(1) == 1381_i);

        target_hook.reset();

        expect(target->add_42(2) == 44_i);
        expect(target->add_43(2) == 45_i);
    };

    "VMT hooking an object maintains correct RTTI"_test = [] {
        struct Interface {
            virtual ~Interface() = default;
            virtual int add_42(int a) = 0;
        };

        struct Target : Interface {
            SAFETYHOOK_NOINLINE int add_42(int a) override { return a + 42; }
        };

        auto target = std::make_unique<Target>();

        expect(target->add_42(0) == 42_i);
        expect(neq(dynamic_cast<Interface*>(target.get()), nullptr));

        static SafetyHookVmt target_hook{};
        static SafetyHookVm add_42_hook{};

        struct Hook : Target {
            int hooked_add_42(int a) { return add_42_hook.thiscall<int>(this, a) + 1337; }
        };

        auto vmt_result = SafetyHookVmt::create(target.get());

        expect(vmt_result.has_value());

        target_hook = std::move(*vmt_result);

        auto vm_result = target_hook.hook_method(1 + VMT_OFFSET, &Hook::hooked_add_42);

        expect(vm_result.has_value());

        add_42_hook = std::move(*vm_result);

        expect(target->add_42(1) == 1380_i);
        expect(neq(dynamic_cast<Interface*>(target.get()), nullptr));
    };

    "Can safely destroy VmtHook after object is deleted"_test = [] {
        struct Interface {
            virtual ~Interface() = default;
            virtual int add_42(int a) = 0;
        };

        struct Target : Interface {
            SAFETYHOOK_NOINLINE int add_42(int a) override { return a + 42; }
        };

        std::unique_ptr<Interface> target = std::make_unique<Target>();

        expect(target->add_42(0) == 42_i);

        static SafetyHookVmt target_hook{};
        static SafetyHookVm add_42_hook{};

        struct Hook : Target {
            int hooked_add_42(int a) { return add_42_hook.thiscall<int>(this, a) + 1337; }
        };

        auto vmt_result = SafetyHookVmt::create(target.get());

        expect(vmt_result.has_value());

        target_hook = std::move(*vmt_result);

        auto vm_result = target_hook.hook_method(1 + VMT_OFFSET, &Hook::hooked_add_42);

        expect(vm_result.has_value());

        add_42_hook = std::move(*vm_result);

        expect(target->add_42(1) == 1380_i);

        target.reset();
        target_hook.reset();
    };

    "Can apply an existing VMT hook to more than one object"_test = [] {
        struct Interface {
            virtual ~Interface() = default;
            virtual int add_42(int a) = 0;
        };

        struct Target : Interface {
            SAFETYHOOK_NOINLINE int add_42(int a) override { return a + 42; }
        };

        std::unique_ptr<Interface> target = std::make_unique<Target>();
        std::unique_ptr<Interface> target0 = std::make_unique<Target>();
        std::unique_ptr<Interface> target1 = std::make_unique<Target>();
        std::unique_ptr<Interface> target2 = std::make_unique<Target>();

        expect(target->add_42(0) == 42_i);

        static SafetyHookVmt target_hook{};
        static SafetyHookVm add_42_hook{};

        struct Hook : Target {
            int hooked_add_42(int a) { return add_42_hook.thiscall<int>(this, a) + 1337; }
        };

        auto vmt_result = SafetyHookVmt::create(target.get());

        expect(vmt_result.has_value());

        target_hook = std::move(*vmt_result);

        auto vm_result = target_hook.hook_method(1 + VMT_OFFSET, &Hook::hooked_add_42);

        expect(vm_result.has_value());

        add_42_hook = std::move(*vm_result);

        target_hook.apply(target0.get());
        target_hook.apply(target1.get());
        target_hook.apply(target2.get());

        expect(target->add_42(1) == 1380_i);
        expect(target0->add_42(1) == 1380_i);
        expect(target1->add_42(1) == 1380_i);
        expect(target2->add_42(1) == 1380_i);

        add_42_hook.reset();

        expect(target->add_42(2) == 44_i);
        expect(target0->add_42(2) == 44_i);
        expect(target1->add_42(2) == 44_i);
        expect(target2->add_42(2) == 44_i);
    };

    "Can remove an object that was previously VMT hooked"_test = [] {
        struct Interface {
            virtual ~Interface() = default;
            virtual int add_42(int a) = 0;
        };

        struct Target : Interface {
            SAFETYHOOK_NOINLINE int add_42(int a) override { return a + 42; }
        };

        std::unique_ptr<Interface> target = std::make_unique<Target>();
        std::unique_ptr<Interface> target0 = std::make_unique<Target>();
        std::unique_ptr<Interface> target1 = std::make_unique<Target>();
        std::unique_ptr<Interface> target2 = std::make_unique<Target>();

        expect(target->add_42(0) == 42_i);

        static SafetyHookVmt target_hook{};
        static SafetyHookVm add_42_hook{};

        struct Hook : Target {
            int hooked_add_42(int a) { return add_42_hook.thiscall<int>(this, a) + 1337; }
        };

        auto vmt_result = SafetyHookVmt::create(target.get());

        expect(vmt_result.has_value());

        target_hook = std::move(*vmt_result);

        auto vm_result = target_hook.hook_method(1 + VMT_OFFSET, &Hook::hooked_add_42);

        expect(vm_result.has_value());

        add_42_hook = std::move(*vm_result);

        target_hook.apply(target0.get());
        target_hook.apply(target1.get());
        target_hook.apply(target2.get());

        expect(target->add_42(1) == 1380_i);
        expect(target0->add_42(1) == 1380_i);
        expect(target1->add_42(1) == 1380_i);
        expect(target2->add_42(1) == 1380_i);

        target_hook.remove(target0.get());

        expect(target->add_42(2) == 1381_i);
        expect(target0->add_42(2) == 44_i);
        expect(target1->add_42(2) == 1381_i);
        expect(target2->add_42(2) == 1381_i);

        target_hook.remove(target2.get());

        expect(target->add_42(2) == 1381_i);
        expect(target0->add_42(2) == 44_i);
        expect(target1->add_42(2) == 1381_i);
        expect(target2->add_42(2) == 44_i);

        target_hook.remove(target.get());

        expect(target->add_42(2) == 44_i);
        expect(target0->add_42(2) == 44_i);
        expect(target1->add_42(2) == 1381_i);
        expect(target2->add_42(2) == 44_i);

        target_hook.remove(target1.get());

        expect(target->add_42(2) == 44_i);
        expect(target0->add_42(2) == 44_i);
        expect(target1->add_42(2) == 44_i);
        expect(target2->add_42(2) == 44_i);
    };

    "VMT hook an object instance with easy API"_test = [] {
        struct Interface {
            virtual ~Interface() = default;
            virtual int add_42(int a) = 0;
        };

        struct Target : Interface {
            SAFETYHOOK_NOINLINE int add_42(int a) override { return a + 42; }
        };

        std::unique_ptr<Interface> target = std::make_unique<Target>();

        expect(target->add_42(0) == 42_i);

        static SafetyHookVmt target_hook{};
        static SafetyHookVm add_42_hook{};

        struct Hook : Target {
            int hooked_add_42(int a) { return add_42_hook.thiscall<int>(this, a) + 1337; }
        };

        target_hook = safetyhook::create_vmt(target.get());
        add_42_hook = safetyhook::create_vm(target_hook, 1 + VMT_OFFSET, &Hook::hooked_add_42);

        expect(target->add_42(1) == 1380_i);

        add_42_hook.reset();

        expect(target->add_42(2) == 44_i);
    };

    "VMT hook preserves dynamic_cast with cross-cast"_test = [] {
        struct Base1 {
            virtual ~Base1() = default;
            virtual int add_42(int a) = 0;
        };

        struct Base2 {
            virtual ~Base2() = default;
            virtual int add_1337(int a) = 0;
        };

        struct Target : Base1, Base2 {
            SAFETYHOOK_NOINLINE int add_42(int a) override { return a + 42; }
            SAFETYHOOK_NOINLINE int add_1337(int a) override { return a + 1337; }
        };

        auto target = std::make_unique<Target>();

        Base2* base2 = target.get();

        static SafetyHookVmt base2_hook{};
        static SafetyHookVm add_1337_hook{};

        struct Hook : Target {
            int hooked_add_1337(int a) { return add_1337_hook.thiscall<int>(this, a) + 42; }
        };

        auto vmt_result = SafetyHookVmt::create(base2);
        expect(vmt_result.has_value());
        base2_hook = std::move(*vmt_result);

        auto vm_result = base2_hook.hook_method(1 + VMT_OFFSET, &Hook::hooked_add_1337);
        expect(vm_result.has_value());
        add_1337_hook = std::move(*vm_result);

        expect(base2->add_1337(1) == 1380_i);

        // Cross-cast: Base2* -> Base1*
        // Runtime reads offset-to-top from Base2's vptr[-2]
        // Without the fix this is garbage and will crash or return wrong pointer
        Base1* base1 = dynamic_cast<Base1*>(base2);
        expect(neq(base1, nullptr));
        expect(base1->add_42(1) == 43_i);

        add_1337_hook.reset();
        base2_hook.reset();
    };
};
