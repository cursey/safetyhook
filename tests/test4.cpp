#include <iostream>

#include <SafetyHook.hpp>

SafetyHookInline g_hook{};

__declspec(noinline) void SayHello(int times) {
    std::cout << "Hello #" << times << std::endl;
}

void Hooked_SayHello(int times) {
    g_hook.call<void, int>(1337);
}

void SayHelloInfinitely() {
    int count = 0;

    while (true) {
        SayHello(count++);
    }
}

int main() {
    // Starting a thread for SayHello
    std::thread t(SayHelloInfinitely);
    t.detach();

    {
        auto builder = SafetyHookFactory::acquire();
        g_hook = builder.create_inline((void*)SayHello, (void*)Hooked_SayHello);
    }

    std::this_thread::sleep_for(std::chrono::seconds(1));

    g_hook.reset();

    std::this_thread::sleep_for(std::chrono::seconds(1));

    return 0;
}