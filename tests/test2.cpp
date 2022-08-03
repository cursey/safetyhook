#include <iostream>

#include <SafetyHook.hpp>

__declspec(noinline) int add_42(int a) {
    return a + 42;
}

void hooked_add_42(safetyhook::Context& ctx) {
    ctx.rax = 1337;
}

SafetyMidHook g_hook{};

int main(int argc, char* argv[]) {
    std::cout << add_42(2) << "\n";

    {
        // Lets hook the RET.
        auto addr = (uintptr_t)add_42;

        while (*(uint8_t*)addr != 0xC3) {
            if (*(uint8_t*)addr == 0xE9) {
                // Follow the jmp.
                addr += *(int32_t*)(addr + 1) + 5;
            } else {
                addr += 1;
            }
        }

        auto factory = SafetyHookFactory::init();
        auto builder = factory->acquire();
        g_hook = builder.create_mid((void*)addr, hooked_add_42);
    }

    std::cout << add_42(3) << "\n";

    g_hook.reset();

    std::cout << add_42(4) << "\n";

    return 0;
}
