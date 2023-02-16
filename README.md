# SafetyHook

SafetyHook is a procedure hooking library for Windows x86 and x86_64 systems. It aims to make runtime procedure hooking as safe as possible while maintaining simplicity of it's implementation. To that end it currently does:

* Stops all other threads when creating or deleting hooks
* Locks the PEB Loader Lock while freezing threads
* Fixes the IP of threads that may be affected by the creation or deletion of hooks
* Fixes IP relative displacements of relocated instructions (eg. `lea rax, [rip + 0x1234]`)
* Fixes relative offsets of relocated instructions (eg. `jmp 0x1234`)
* Uses a modern disassembler engine that supports the latest instructions
* Has a carefully designed API that is hard to misuse

## Installation

SafetyHook depends on [bddisasm](https://github.com/bitdefender/bddisasm) so your project must also include it as well. Both libraries can be added via CMake's `FetchContent`, git submodules, or copied directly into your project.

### FetchContent

```CMake
include(FetchContent)

# Bddisasm
FetchContent_Declare(
    bddisasm
    GIT_REPOSITORY "https://github.com/bitdefender/bddisasm.git"
    GIT_TAG "origin/master"
)
FetchContent_MakeAvailable(bddisasm)

# Safetyhook
FetchContent_Declare(
    safetyhook
    GIT_REPOSITORY "https://github.com/cursey/safetyhook.git"
    GIT_TAG "origin/main"
)
FetchContent_MakeAvailable(safetyhook)

```

## Usage

```C++
#include <iostream>

#include <SafetyHook.hpp>

int add(int x, int y) {
    return x + y;
}

SafetyHookInline g_add_hook{};

int hook_add(int x, int y) {
    return g_add_hook.call<int>(x * 2, y * 2);
}

int main(int argc, char* argv[]) {
    std::cout << "unhooked add(2, 3) = " << add(2, 3) << "\n";

    {
        // Acquire the factory's builder which will freeze all threads and give
        // us access to the hook creation methods.
        auto builder = SafetyHookFactory::acquire(); 

        // Create a hook on add.
        g_add_hook = builder.create_inline(add, hook_add);

        // Once we leave this scope, builder will unfreeze all threads and our
        // factory will be kept alive by g_add_hook.
    }

    std::cout << "hooked add(2, 3) = " << add(2, 3) << "\n";

    g_add_hook = {};

    std::cout << "unhooked add(2, 3) = " << add(2, 3) << "\n";

    return 0;
}
```
