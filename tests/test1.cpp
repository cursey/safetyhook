#include <iostream>

#include <safetyhook.hpp>

__declspec(noinline) int add(int x, int y) {
    return x + y;
}

SafetyHookInline g_add_hook{};

int hook_add(int x, int y) {
    return g_add_hook.call<int>(x * 2, y * 2);
}

int main() {
    std::cout << "unhooked add(2, 3) = " << add(2, 3) << "\n";

    // Create a hook on add.
    g_add_hook = safetyhook::create_inline((void*)add, (void*)hook_add);

    std::cout << "hooked add(3, 4) = " << add(3, 4) << "\n";

    g_add_hook = {};

    std::cout << "unhooked add(5, 6) = " << add(5, 6) << "\n";

    return 0;
}