#include <iostream>

#include <SafetyHook.hpp>
#include <Zydis.h>

__declspec(noinline) int add_42(int a) {
    return a + 42;
}

void hooked_add_42(SafetyHookContext& ctx) {
#ifdef _M_X64
    ctx.rax = 1337;
#else
    ctx.eax = 1337;
#endif
}

SafetyHookMid g_hook{};

int main() {
    std::cout << add_42(2) << "\n";

    {
        // Lets disassemble add_42 and hook its RET.
        ZydisDecoder decoder{};

#if defined(_M_X64)
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
#elif defined(_M_IX86)
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);
#else
#error "Unsupported architecture"
#endif

        auto ip = (uintptr_t)add_42;

        while (*(uint8_t*)ip != 0xC3) {
            ZydisDecodedInstruction ix{};

            ZydisDecoderDecodeInstruction(&decoder, nullptr, (const void*)ip, 15, &ix);

            // Follow JMPs
            if (ix.opcode == 0xE9) {
                ip += ix.length + (int32_t)ix.raw.imm[0].value.s;
            } else {
                ip += ix.length;
            }
        }

        auto builder = SafetyHookFactory::acquire();
        g_hook = builder.create_mid((void*)ip, hooked_add_42);
    }

    std::cout << add_42(3) << "\n";

    g_hook.reset();

    std::cout << add_42(4) << "\n";

    return 0;
}
