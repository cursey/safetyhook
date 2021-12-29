#include <algorithm>
#include <cassert>
#include <functional>

#include <Windows.h>

#include "SafetyHookFactory.hpp"

uintptr_t SafetyHookFactory::allocate(size_t size) {
    return allocate_near({0}, size, 0xFFFF'FFFF'FFFF'FFFF);
}

uintptr_t SafetyHookFactory::allocate_near(const std::vector<uintptr_t>& desired_addresses, size_t size, size_t max_distance) {
    std::scoped_lock _{m_mux};

    // First search through our list of allocations for a free block that is large enough.
    for (auto& allocation : m_allocations) {
        if (allocation->size < size) {
            continue;
        }

        for (auto node = allocation->freelist.get(); node != nullptr; node = node->next.get()) {
            // Enough room?
            if (node->end - node->start < size) {
                continue;
            }

            auto address = node->start;

            // Close enough?
            if (!in_range(address, desired_addresses, max_distance)) {
                continue;
            }

            node->start += size;

            return address;
        }
    }

    // If we didn't find a free block, we need to allocate a new one.
    auto allocation_size = ((size + 0x1000 - 1) / 0x1000) * 0x1000;
    auto allocation_address = allocate_nearby_memory(desired_addresses, allocation_size, max_distance);

    if (allocation_address == 0) {
        return 0;
    }

    auto& allocation = m_allocations.emplace_back(new MemoryAllocation);

    allocation->address = allocation_address;
    allocation->size = allocation_size;
    allocation->freelist = std::make_unique<FreeNode>();
    allocation->freelist->start = allocation_address + size;
    allocation->freelist->end = allocation_address + allocation_size;

    return allocation_address;
}

void SafetyHookFactory::free(uintptr_t address, size_t size) {
    std::scoped_lock _{m_mux};

    for (auto& allocation : m_allocations) {
        if (allocation->address > address || allocation->address + allocation->size < address) {
            continue;
        }

        struct OnExit {
            std::function<void()> fn{};
            ~OnExit() { fn(); }
        } on_exit{[&allocation, this] { combine_adjacent_freenodes(*allocation); }};

        for (auto node = allocation->freelist.get(), prev = (FreeNode*)0; node != nullptr; node = node->next.get()) {
            // Expand adjacent freenode (coming after).
            if (node->start == address + size) {
                node->start -= size;
                return;
            }

            // Expand adjacent freenode (coming before).
            if (node->end == address) {
                node->end += size;
                return;
            }

            // Expand containing freenode.
            if (node->start == address) {
                node->end = std::max(node->end, address + size);
                return;
            }

            // Add new freenode.
            if (node->start > address) {
                auto free_node = std::make_unique<FreeNode>();

                free_node->start = address;
                free_node->end = address + size;

                if (prev == nullptr) {
                    free_node->next.swap(allocation->freelist);
                    allocation->freelist.swap(free_node);
                } else {
                    free_node->next.swap(prev->next);
                    prev->next.swap(free_node);
                }

                return;
            }
        }

        assert(0);
    }
}

void SafetyHookFactory::combine_adjacent_freenodes(MemoryAllocation& allocation) {
    for (auto prev = allocation.freelist.get(), node = prev; node != nullptr; node = node->next.get()) {
        if (prev->end == node->start) {
            prev->end = node->end;
            prev->next.swap(node->next);
            node->next.reset();
            node = prev;
        } else {
            prev = node;
        }
    }
}

uintptr_t SafetyHookFactory::allocate_nearby_memory(const std::vector<uintptr_t>& desired_addresses, size_t size, size_t max_distance) {
    auto attempt_allocation = [&](uintptr_t p) -> uintptr_t {
        if (!in_range(p, desired_addresses, max_distance)) {
            return 0;
        }

        return (uintptr_t)VirtualAlloc((LPVOID)p, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    };

    SYSTEM_INFO si{};

    GetSystemInfo(&si);

    for (auto desired_address : desired_addresses) {
        auto search_start = std::min(desired_address, desired_address - max_distance);
        auto search_end = std::max(desired_address, desired_address + max_distance);
        search_start = std::max(search_start, (uintptr_t)si.lpMinimumApplicationAddress);
        search_end = std::min(search_end, (uintptr_t)si.lpMaximumApplicationAddress);
        desired_address = std::clamp(((desired_address + 0x1000 - 1) / 0x1000) * 0x1000, search_start, search_end);
        MEMORY_BASIC_INFORMATION mbi{};

        // Search backwards from the desired_address.
        for (auto p = desired_address; p > search_start; p -= 0x1000) {
            if (VirtualQuery((LPCVOID)p, &mbi, sizeof(mbi)) == 0) {
                break;
            }

            if (mbi.State != MEM_FREE) {
                continue;
            }

            if (auto allocation_address = attempt_allocation(p); allocation_address != 0) {
                return allocation_address;
            }
        }

        // Search forwards from the desired_address.
        for (auto p = desired_address; p < search_end; p += mbi.RegionSize) {
            if (VirtualQuery((LPCVOID)p, &mbi, sizeof(mbi)) == 0) {
                break;
            }

            if (mbi.State != MEM_FREE) {
                continue;
            }

            if (auto allocation_address = attempt_allocation(p); allocation_address != 0) {
                return allocation_address;
            }
        }
    }

    return 0;
}

bool SafetyHookFactory::in_range(uintptr_t address, const std::vector<uintptr_t>& desired_addresses, size_t max_distance) {
    auto is_in_range = true;

    for (auto&& desired_address : desired_addresses) {
        auto delta = (address > desired_address) ? address - desired_address : desired_address - address;
        if (delta > max_distance) {
            is_in_range = false;
        }
    }

    return is_in_range;
}

SafetyHookFactory::MemoryAllocation::~MemoryAllocation() {
    VirtualFree((LPVOID)address, 0, MEM_RELEASE);
}
