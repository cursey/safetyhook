#include <catch2/catch_test_macros.hpp>
#include <safetyhook.hpp>

TEST_CASE("Allocator reuses freed memory", "[allocator]") {
    const auto allocator = std::make_shared<safetyhook::Allocator>();
    const auto first_allocation = allocator->allocate(128);

    REQUIRE(first_allocation);

    const auto second_allocation = allocator->allocate(256);

    REQUIRE(second_allocation);
    REQUIRE(*second_allocation != *first_allocation);

    allocator->free(*first_allocation, 128);

    const auto third_allocation = allocator->allocate(64);

    REQUIRE(third_allocation);
    REQUIRE(*third_allocation == *first_allocation);

    const auto fourth_allocation = allocator->allocate(64);

    REQUIRE(fourth_allocation);
    REQUIRE(*fourth_allocation == *third_allocation + 64);

    allocator->free(*fourth_allocation, 64);
    allocator->free(*third_allocation, 64);
    allocator->free(*second_allocation, 256);
}