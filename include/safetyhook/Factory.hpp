#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <vector>

#include "MidHook.hpp"
#include "InlineHook.hpp"
#include "ThreadFreezer.hpp"

namespace safetyhook {
class Factory : public std::enable_shared_from_this<Factory> {
public:
    class Builder {
    public:
        ~Builder();

        std::unique_ptr<InlineHook> create_inline(void* target, void* destination);
        std::unique_ptr<MidHook> create_mid(void* target, MidHookFn destination);
        
    private:
        friend InlineHook;
        friend Factory;

        std::shared_ptr<Factory> m_factory{};
        std::scoped_lock<std::mutex> m_lock;
        ThreadFreezer m_threads{};

        explicit Builder(std::shared_ptr<Factory> f);
    };

    static auto init() { return std::shared_ptr<Factory>{new Factory}; }

    Builder acquire();

private:
    friend InlineHook;
    friend MidHook;

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

    Factory() = default;

    std::unique_ptr<InlineHook> create_inline(void* target, void* destination);
    std::unique_ptr<MidHook> create_mid(void* target, MidHookFn destination);

    uintptr_t allocate(size_t size);
    uintptr_t allocate_near(
        const std::vector<uintptr_t>& desired_addresses, size_t size, size_t max_distance = 0x7FFF'FFFF);
    void free(uintptr_t address, size_t size);

    void combine_adjacent_freenodes(MemoryAllocation& allocation);
    uintptr_t allocate_nearby_memory(const std::vector<uintptr_t>& desired_addresses, size_t size, size_t max_distance);
    bool in_range(uintptr_t address, const std::vector<uintptr_t>& desired_addresses, size_t max_distance);
};
} // namespace safetyhook