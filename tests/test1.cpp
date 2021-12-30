
#include <iostream>

#include <SafetyHook.hpp>

int add(int x, int y) {
    return x + y;
}

std::unique_ptr<SafetyHook> g_add_hook{};

int hook_add(int x, int y) {
    return g_add_hook->call<int>(x * 2, y * 2);
}

int main(int argc, char* argv[]) {
    std::cout << "unhooked add(2, 3) = " << add(2, 3) << "\n";

    auto factory = SafetyHookFactory::init();

    {
        // Builder keeps all threads frozen until it goes out of scope.
        auto builder = factory->acquire();
        g_add_hook = builder.create(add, hook_add);
    }

    std::cout << "hooked add(2, 3) = " << add(2, 3) << "\n";

    g_add_hook.reset();

    std::cout << "unhooked add(2, 3) = " << add(2, 3) << "\n";

    return 0;
}