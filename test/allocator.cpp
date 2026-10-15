#include <cerrno>

#include <gtest/gtest.h>
#include <safetyhook.hpp>

#if SAFETYHOOK_OS_LINUX
#include <sys/mman.h>
#include <unistd.h>

TEST(Allocator, DestructionUnmapsOnlyItsOwnMemory) {
    const auto page_size = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    auto other_allocator = safetyhook::Allocator::create();
    auto other_allocation = other_allocator->allocate(page_size);
    ASSERT_TRUE(other_allocation.has_value());

    uint8_t* address{};
    {
        auto allocator = safetyhook::Allocator::create();
        auto allocation = allocator->allocate(page_size);
        ASSERT_TRUE(allocation.has_value());
        address = allocation->data();
    }

    unsigned char residency{};
    errno = 0;
    EXPECT_EQ(mincore(address, page_size, &residency), -1);
    EXPECT_EQ(errno, ENOMEM);
    EXPECT_EQ(mincore(other_allocation->data(), page_size, &residency), 0);
}
#endif

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
