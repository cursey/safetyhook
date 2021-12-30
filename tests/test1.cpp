#include <iostream>

#include <SafetyHook.hpp>

__declspec(noinline) int add(int x, int y) {
    return x + y;
}

std::unique_ptr<SafetyHook> g_add_hook{};

int hook_add(int x, int y) {
    return g_add_hook->call<int>(x * 2, y * 2);
}

int main(int argc, char* argv[]) {
    std::cout << "unhooked add(2, 3) = " << add(2, 3) << "\n";

    {
        // Create a factory that will create hooks for us.
        auto factory = SafetyHookFactory::init();

        // Acquire the factory's builder which will freeze all threads and give
        // us access to the hook creation methods.
        auto builder = factory->acquire();

        // Create a hook on add.
        g_add_hook = builder.create(add, hook_add);

        // Once we leave this scope, builder will unfreeze all threads and our
        // factory will be kept alive by g_add_hook.
    }

    std::cout << "hooked add(2, 3) = " << add(2, 3) << "\n";

    g_add_hook.reset();

    std::cout << "unhooked add(2, 3) = " << add(2, 3) << "\n";

    return 0;
}