// test5.cpp is test0.cpp but with 2GB of memory reserved around the target address.
// This is to test if the allocator works correctly when there is no free memory near the target address.
#include <iostream>
#include <iomanip>
#include <sstream>
#include <format>
#include <cstdint>

#include <safetyhook.hpp>

#if __has_include(<Zydis/Zydis.h>)
#include <Zydis/Zydis.h>
#elif __has_include(<Zydis.h>)
#include <Zydis.h>
#else
#error "Zydis not found"
#endif

auto operator ""_mb(unsigned long long mb) {
    return mb * 1024 * 1024;
}

auto operator ""_gb(unsigned long long gb) {
    return gb * 1024 * 1024 * 1024;
}

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

// Intentionally takes up memory space +- 2GB around the target address.
// so we can test if the allocator works correctly.
void reserve_memory_2gb_around_target(uintptr_t target) {
    // First we must obtain all currently allocated memory regions.
    std::vector<std::pair<uintptr_t, uintptr_t>> regions{};
    std::vector<std::pair<uintptr_t, uintptr_t>> free_regions{};

    MEMORY_BASIC_INFORMATION mbi{};
    uintptr_t address = 0;

    while (VirtualQuery(reinterpret_cast<void*>(address), &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT) {
            regions.emplace_back(reinterpret_cast<uintptr_t>(mbi.BaseAddress), reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize);
        } else if (mbi.State == MEM_FREE) {
            free_regions.emplace_back(reinterpret_cast<uintptr_t>(mbi.BaseAddress), reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize);
        }

        address += mbi.RegionSize;
    }
    
    std::vector<std::pair<uintptr_t, uintptr_t>> new_regions{};

    // Go through the free regions and reserve memory if
    // the distance to the target is less than 2GB.
    for (auto& region : free_regions) {
        if (region.first > target && region.second > target && region.first - target <= 2_gb) {
            new_regions.emplace_back(region);
        } else if (region.first < target && region.second < target && target - region.second <= 2_gb) {
            new_regions.emplace_back(region);
        }
    }

    // get allocation granularity
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    
    const auto granularity = (size_t)si.dwAllocationGranularity;

    std::cout << std::format("Allocation granularity: 0x{:x}\n", granularity);

    // Split the regions into 10mb chunks.
    for (auto& region : new_regions) {
        std::cout << std::format("Region: 0x{:x} 0x{:x}\n", region.first, region.second);

        // We do this because when passing a null pointer to VirtualAlloc, it will allocate a region that *isn't* at address 0.
        // So we need to find the nearest address that is aligned to the allocation granularity instead.
        if (region.first == 0) {
            region.first += 1;
        }

        const auto new_first = (region.first + (granularity - 1)) & ~(granularity - 1);

        if (new_first < region.second) {
            region.first = new_first;
        } else {
            // uh... this shouldn't happen. but it does on 32-bit.
            std::cout << "Region is too small\n";
            continue;
        }

        const auto size = region.second - region.first;
        const auto tenmb_aligned = (10_mb + (granularity - 1)) & ~(granularity - 1);
        const auto chunk_size = (std::min<size_t>((size_t)tenmb_aligned, size));

        // uh...
        if (chunk_size == 0) {
            std::cout << "Chunk size is 0\n";
            continue;
        }

        const auto num_chunks = size / chunk_size;

        for (size_t i = 0; i < num_chunks; ++i) {
            const auto wanted_alloc = region.first + i * chunk_size;
            const auto alloced = VirtualAlloc((void*)wanted_alloc, chunk_size, MEM_RESERVE, PAGE_READWRITE);

            if (alloced == nullptr) {
                const auto error = GetLastError();
                std::cout << std::format("Failed to allocate to 0x{:x} 0x{:x}\n", wanted_alloc, chunk_size);
                std::cout << std::format("Error: 0x{:x}\n", error);
            } else {
                std::cout << std::format("Allocated [0x{:x}, 0x{:x}] 0x{:x}\n", (uintptr_t)alloced, (uintptr_t)alloced + chunk_size, chunk_size);
            }
        }

        // Handle remaining small fragment
        auto remaining = size % chunk_size;
        if (remaining > 0) {
            std::cout << std::format("Allocating remaining 0x{:x}\n", remaining);
            auto last_alloc = region.first + num_chunks * chunk_size;
            auto alloced = VirtualAlloc((void*)last_alloc, remaining, MEM_RESERVE, PAGE_READWRITE);

            if (alloced == nullptr) {
                const auto error = GetLastError();
                std::cout << std::format("Failed to allocate to 0x{:x} 0x{:x}\n", last_alloc, remaining);
                std::cout << std::format("Error: 0x{:x}\n", error);
            } else {
                std::cout << std::format("Allocated [0x{:x}, 0x{:x}] 0x{:x}\n", (uintptr_t)alloced, (uintptr_t)alloced + remaining, remaining);
            }
        }
    }
}

int main() {
    // Comment this out to double check the JMP verification that's below.
    reserve_memory_2gb_around_target(reinterpret_cast<uintptr_t>(&say_hi));

    std::cout << std::format("0x{:x}\n", (uintptr_t)&say_hi);

    uintptr_t real_say_hi = (uintptr_t)&say_hi;

    if (*(uint8_t*)&say_hi == 0xE9) {
        real_say_hi = (uintptr_t)&say_hi + *(int32_t*)((uintptr_t)&say_hi + 1) + 5;
        std::cout << std::format("0x{:x}\n", (uintptr_t)real_say_hi);
    }

    ZydisDecoder decoder{};

#if defined(_M_X64)
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
#elif defined(_M_IX86)
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);
#else
#error "Unsupported architecture"
#endif

    ZydisFormatter formatter{};
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
    ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_FORCE_SEGMENT, ZYAN_TRUE);
    ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE);

    auto disassemble_say_hi = [&]() {
        uintptr_t ip = real_say_hi;
        for (auto i = 0; i < 10; ++i) {
            ZydisDecodedInstruction ix{};
            ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
            ZydisDecoderDecodeFull(&decoder, reinterpret_cast<void*>(ip), 15, &ix, operands);

            // Convert to text
            char buffer[256]{};
            ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
            ZydisFormatterFormatInstruction(&formatter, &ix, operands, ZYDIS_MAX_OPERAND_COUNT, buffer, sizeof(buffer), ip, nullptr);

            // Format to {bytes} {mnemonic} {operands}
            std::stringstream bytehex{};

            for (auto j = 0; j < ix.length; ++j) {
                bytehex << std::hex << std::setfill('0') << std::setw(2) << (int)*(uint8_t*)(ip + j) << " ";
            }

            std::cout << std::format("0x{:x} | {} | {}\n", ip, bytehex.str(), buffer);

            ip += ix.length;
        }
    };

    std::cout << "Before:" << std::endl;
    disassemble_say_hi();

    hook0 = safetyhook::create_inline(reinterpret_cast<void*>(real_say_hi), reinterpret_cast<void*>(hook0_fn));

    if (!hook0) {
        std::cout << "Failed to create hook\n";
        return 1;
    }

    hook1 = safetyhook::create_inline(reinterpret_cast<void*>(real_say_hi), reinterpret_cast<void*>(hook1_fn));
    hook2 = safetyhook::create_inline(reinterpret_cast<void*>(real_say_hi), reinterpret_cast<void*>(hook2_fn));
    hook3 = safetyhook::create_inline(reinterpret_cast<void*>(real_say_hi), reinterpret_cast<void*>(hook3_fn));

    std::cout << "After:" << std::endl;
    disassemble_say_hi();

    // Ensure that the jmp at the beginning of real_say_hi points to a nearby address, in the current region of memory.
    // Because that's the point of this test, to test if the allocator works correctly when there is no free memory near the target address.
    if (*(uint8_t*)real_say_hi == 0xE9) {
        const auto jmp_point = real_say_hi + *(int32_t*)(real_say_hi + 1) + 5;

        MEMORY_BASIC_INFORMATION mbi_real_say_hi{};
        MEMORY_BASIC_INFORMATION mbi_jmp_point{};

        VirtualQuery(reinterpret_cast<void*>(real_say_hi), &mbi_real_say_hi, sizeof(mbi_real_say_hi));
        VirtualQuery(reinterpret_cast<void*>(jmp_point), &mbi_jmp_point, sizeof(mbi_jmp_point));

        if (mbi_real_say_hi.AllocationBase == mbi_jmp_point.AllocationBase &&
            mbi_real_say_hi.BaseAddress == mbi_jmp_point.BaseAddress)
        {
            std::cout << "JMP points to nearby address: SUCCESS\n";
        } else {
            std::cout << "JMP points to nearby address: FAILED\n";
        }
    } else if (*(uint8_t*)real_say_hi == 0xFF && *(uint8_t*)(real_say_hi + 1) == 0x25) {
        const auto displacement = *(int32_t*)(real_say_hi + 2);
        const auto reference_addr = real_say_hi + displacement + 6;
        const auto jmp_point = *(uintptr_t*)reference_addr;

        MEMORY_BASIC_INFORMATION mbi_real_say_hi{};
        MEMORY_BASIC_INFORMATION mbi_jmp_point{};

        VirtualQuery(reinterpret_cast<void*>(real_say_hi), &mbi_real_say_hi, sizeof(mbi_real_say_hi));
        VirtualQuery(reinterpret_cast<void*>(jmp_point), &mbi_jmp_point, sizeof(mbi_jmp_point));

        if (mbi_real_say_hi.AllocationBase == mbi_jmp_point.AllocationBase &&
            mbi_real_say_hi.BaseAddress == mbi_jmp_point.BaseAddress)
        {
            std::cout << "JMP points to nearby address: SUCCESS\n";
        } else {
            std::cout << "JMP points to nearby address: FAILED\n";
        }
    }

    say_hi("world");

    return 0;
}