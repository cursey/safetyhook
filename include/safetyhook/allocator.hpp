#pragma once

#include <cstdint>
#include <expected>
#include <memory>
#include <mutex>
#include <vector>

namespace safetyhook {
class Allocator final {
public:
    [[nodiscard]] static std::shared_ptr<Allocator> global();

    Allocator() = default;
    Allocator(const Allocator&) = delete;
    Allocator(Allocator&&) noexcept = default;
    Allocator& operator=(const Allocator&) = delete;
    Allocator& operator=(Allocator&&) noexcept = default;
    ~Allocator() = default;

    enum class Error {
        BAD_VIRTUAL_ALLOC,
        NO_MEMORY_IN_RANGE,
    };

    [[nodiscard]] std::expected<uintptr_t, Error> allocate(size_t size);
    [[nodiscard]] std::expected<uintptr_t, Error> allocate_near(
        const std::vector<uintptr_t>& desired_addresses, size_t size, size_t max_distance = 0x7FFF'FFFF);
    void free(uintptr_t address, size_t size);

private:
    struct FreeNode {
        std::unique_ptr<FreeNode> next{};
        uintptr_t start{};
        uintptr_t end{};
    };

    struct MemoryAllocation {
        uintptr_t address{};
        size_t size{};
        std::unique_ptr<FreeNode> freelist{};

        ~MemoryAllocation();
    };

    std::vector<std::unique_ptr<MemoryAllocation>> m_allocations{};
    std::mutex m_mutex{};

    void combine_adjacent_freenodes(MemoryAllocation& allocation);
    [[nodiscard]] std::expected<uintptr_t, Error> allocate_nearby_memory(
        const std::vector<uintptr_t>& desired_addresses, size_t size, size_t max_distance);
    [[nodiscard]] bool in_range(
        uintptr_t address, const std::vector<uintptr_t>& desired_addresses, size_t max_distance);
};
} // namespace safetyhook