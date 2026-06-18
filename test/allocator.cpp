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
