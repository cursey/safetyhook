#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <vector>

#include "SafetyHook.hpp"

class SafetyHookFactory : public std::enable_shared_from_this<SafetyHookFactory> {
public:
    static auto init() { return std::shared_ptr<SafetyHookFactory>{new SafetyHookFactory}; }

    auto create(void* target, void* destination) {
        return std::unique_ptr<SafetyHook>{
            new SafetyHook{shared_from_this(), (uintptr_t)target, (uintptr_t)destination}};
    }

    auto create_shared(void* target, void* destination) {
        return std::shared_ptr<SafetyHook>{
            new SafetyHook{shared_from_this(), (uintptr_t)target, (uintptr_t)destination}};
    }

private:
    friend SafetyHook;

    struct FreeListNode {
        std::unique_ptr<FreeListNode> next{};
        uintptr_t address{};
        size_t size{};
    };

    struct MemoryAllocation {
        uintptr_t address{};
        size_t size{};
        std::unique_ptr<FreeListNode> free_list{};

        ~MemoryAllocation();
    };

    std::vector<std::unique_ptr<MemoryAllocation>> m_allocations{};
    std::mutex m_mux{};

    SafetyHookFactory() = default;

    uintptr_t allocate(size_t size);
    uintptr_t allocate_near(uintptr_t desired_address, size_t size, size_t max_distance = 0xFFFF'FFFF);
    void free(uintptr_t address, size_t size);

    void combine_adjacent_freenodes(MemoryAllocation& allocation);
    uintptr_t find_memory_near(uintptr_t desired_address, size_t size, size_t max_distance);
};