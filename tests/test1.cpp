#include <iostream>

#include <SafetyHook.hpp>

__declspec(noinline) int add(int x, int y) {
    return x + y;
}

SafetyHookInline g_add_hook{};

int hook_add(int x, int y) {
    return g_add_hook.call<int>(x * 2, y * 2);
}

int main() {
    std::cout << "unhooked add(2, 3) = " << add(2, 3) << "\n";

    {
        // Acquire the factory's builder which will freeze all threads and give
        // us access to the hook creation methods.
        auto builder = SafetyHookFactory::acquire();

        // Create a hook on add.
        g_add_hook = builder.create_inline((void*)add, (void*)hook_add);

        // Once we leave this scope, builder will unfreeze all threads and our
        // factory will be kept alive by g_add_hook.
    }

    std::cout << "hooked add(3, 4) = " << add(3, 4) << "\n";

    g_add_hook = {};

    std::cout << "unhooked add(5, 6) = " << add(5, 6) << "\n";

    return 0;
}