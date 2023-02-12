#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <vector>

#include "InlineHook.hpp"
#include "MidHook.hpp"
#include "ThreadFreezer.hpp"

namespace safetyhook {
class Factory final : public std::enable_shared_from_this<Factory> {
public:
    class Builder final {
    public:
        Builder(const Builder&) = delete;
        Builder(Builder&&) noexcept = delete;
        Builder& operator=(const Builder&) = delete;
        Builder& operator=(Builder&&) noexcept = delete;

        ~Builder();

        [[nodiscard]] std::unique_ptr<InlineHook> create_inline(void* target, void* destination);
        [[nodiscard]] std::unique_ptr<MidHook> create_mid(void* target, MidHookFn destination);

    private:
        friend Factory;
        friend InlineHook;
        friend MidHook;

        std::shared_ptr<Factory> m_factory{};
        std::shared_ptr<ThreadFreezer> m_threads{};

        explicit Builder(std::shared_ptr<Factory> f);

        void fix_ip(uintptr_t old_ip, uintptr_t new_ip);
        [[nodiscard]] uintptr_t allocate(size_t size);
        [[nodiscard]] uintptr_t allocate_near(
            const std::vector<uintptr_t>& desired_addresses, size_t size, size_t max_distance = 0x7FFF'FFFF);
        void free(uintptr_t address, size_t size);
    };

    [[nodiscard]] static Builder acquire();

    ~Factory();

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
    std::mutex m_mux{};
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