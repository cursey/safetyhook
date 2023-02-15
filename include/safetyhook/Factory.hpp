#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <vector>

#include "safetyhook/Builder.hpp"

namespace safetyhook {
class Factory final : public std::enable_shared_from_this<Factory> {
public:
    [[nodiscard]] static Builder acquire();

    Factory(const Factory&) = delete;
    Factory(Factory&&) noexcept = delete;
    Factory& operator=(const Factory&) = delete;
    Factory& operator=(Factory&&) noexcept = delete;

    ~Factory();

private:
    friend Builder;

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
    Builder* m_builder{};

    Factory();

    [[nodiscard]] uintptr_t allocate(size_t size);
    [[nodiscard]] uintptr_t allocate_near(
        const std::vector<uintptr_t>& desired_addresses, size_t size, size_t max_distance = 0x7FFF'FFFF);
    void free(uintptr_t address, size_t size);

    void combine_adjacent_freenodes(MemoryAllocation& allocation);
    [[nodiscard]] uintptr_t allocate_nearby_memory(
        const std::vector<uintptr_t>& desired_addresses, size_t size, size_t max_distance);
    [[nodiscard]] bool in_range(
        uintptr_t address, const std::vector<uintptr_t>& desired_addresses, size_t max_distance);
};
} // namespace safetyhook