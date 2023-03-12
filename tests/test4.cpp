#include <iostream>

#include <safetyhook.hpp>

constexpr const char g_label[] = "Hello";

__attribute__((naked)) const char* get_str()
{
    __asm
    {
        lea rax, ds:g_label
        ret
    }
}

const char* get_str_hook()
{
    return "Hello, World!";
}

SafetyHookInline g_get_str_hook{};

int main() {
    std::cout << "unhooked get_str() = " << get_str() << "\n";

    // g_get_str_hook = safetyhook::create_inline((void*)get_str, (void*)get_str_hook);

    const auto hook = SafetyHookInline::create((void*)get_str, (void*)get_str_hook);

    printf("err %i\n", hook.error().type);

    std::cout << "hooked get_str() = " << get_str() << "\n";

    g_get_str_hook = {};

    std::cout << "unhooked get_str() = " << get_str() << "\n";

    return 0;
}