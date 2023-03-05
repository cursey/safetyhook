#include <catch2/catch_test_macros.hpp>
#include <safetyhook.hpp>

TEST_CASE("Allocator reuses freed memory", "[allocator]") {
    const auto allocator = safetyhook::Allocator::create();
    auto first_allocation = allocator->allocate(128);

    REQUIRE(first_allocation);

    const auto first_allocation_address = first_allocation->address();
    const auto second_allocation = allocator->allocate(256);

    REQUIRE(second_allocation);
    REQUIRE(second_allocation->address() != first_allocation_address);

    first_allocation->free();

    const auto third_allocation = allocator->allocate(64);

    REQUIRE(third_allocation);
    REQUIRE(third_allocation->address() == first_allocation_address);

    const auto fourth_allocation = allocator->allocate(64);

    REQUIRE(fourth_allocation);
    REQUIRE(fourth_allocation->address() == third_allocation->address() + 64);
}