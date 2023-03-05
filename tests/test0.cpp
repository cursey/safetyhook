#include <iostream>

#include <safetyhook.hpp>

SafetyHookInline hook0, hook1, hook2, hook3;

__declspec(noinline) void say_hi(const std::string& name) {
    std::cout << "hello " << name << "\n";
}

void hook0_fn(const std::string& name) {
    hook0.call<void, const std::string&>(name + " and bob");
}

void hook1_fn(const std::string& name) {
    hook1.call<void, const std::string&>(name + " and alice");
}

void hook2_fn(const std::string& name) {
    hook2.call<void, const std::string&>(name + " and eve");
}

void hook3_fn(const std::string& name) {
    hook3.call<void, const std::string&>(name + " and carol");
}

int main() {
    {
        hook0 = *SafetyHookInline::create((void*)say_hi, (void*)hook0_fn);
        hook1 = *SafetyHookInline::create((void*)say_hi, (void*)hook1_fn);
        hook2 = *SafetyHookInline::create((void*)say_hi, (void*)hook2_fn);
        hook3 = *SafetyHookInline::create((void*)say_hi, (void*)hook3_fn);
    }

    say_hi("world");

    return 0;
}