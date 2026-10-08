#include <gtest/gtest.h>
#include <safetyhook.hpp>

TEST(Allocator, AllocatorReusesFreedMemory) {
    const auto allocator = safetyhook::Allocator::create();
    auto first_allocation = allocator->allocate(128);

    ASSERT_TRUE(first_allocation.has_value());

    const auto first_allocation_address = first_allocation->address();
    const auto second_allocation = allocator->allocate(256);

    ASSERT_TRUE(second_allocation.has_value());
    EXPECT_NE(second_allocation->address(), first_allocation_address);

    first_allocation->free();

    const auto third_allocation = allocator->allocate(64);

    ASSERT_TRUE(third_allocation.has_value());
    EXPECT_EQ(third_allocation->address(), first_allocation_address);

    const auto fourth_allocation = allocator->allocate(64);

    ASSERT_TRUE(fourth_allocation.has_value());
    EXPECT_EQ(fourth_allocation->address(), third_allocation->address() + 64);
}

#if SAFETYHOOK_OS_WINDOWS
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

// A free region rarely starts on the allocation granularity (64 KB), but it can still hold an aligned block.
TEST(Allocator, AllocateNearUsesAlignedBlockInsideUnalignedFreeRegion) {
    constexpr size_t KB = 1024;

    // Find 2 MB of free address space.
    auto* base = static_cast<uint8_t*>(VirtualAlloc(nullptr, 2048 * KB, MEM_RESERVE, PAGE_NOACCESS));
    ASSERT_NE(base, nullptr);
    VirtualFree(base, 0, MEM_RELEASE);

    // [base, base+1028K) reserved, [base+1028K, base+1152K) free, [base+1152K, base+2048K) reserved:
    // the free region starts 4 KB past a 64 KB boundary and holds the aligned block [base+1088K, base+1152K).
    auto* low = VirtualAlloc(base, 1028 * KB, MEM_RESERVE, PAGE_NOACCESS);
    auto* high = VirtualAlloc(base + 1152 * KB, 896 * KB, MEM_RESERVE, PAGE_NOACCESS);
    ASSERT_EQ(low, base);
    ASSERT_EQ(high, base + 1152 * KB);

    {
        const auto allocator = safetyhook::Allocator::create();
        const auto allocation = allocator->allocate_near({base + 1024 * KB}, 16, 256 * KB);

        ASSERT_TRUE(allocation.has_value());
        EXPECT_EQ(allocation->data(), base + 1088 * KB);
    }

    VirtualFree(low, 0, MEM_RELEASE);
    VirtualFree(high, 0, MEM_RELEASE);
}
#endif
