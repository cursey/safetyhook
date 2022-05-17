#include <algorithm>
#include <cassert>
#include <functional>
#include <limits>

#include <Windows.h>

#include "safetyhook/ThreadFreezer.hpp"

#include "safetyhook/Factory.hpp"

namespace safetyhook {
constexpr auto align_up(uintptr_t address, size_t align) {
    return (address + align - 1) & ~(align - 1);
}

constexpr auto align_down(uintptr_t address, size_t align) {
    return address & ~(align - 1);
}

Factory::Builder::~Builder() {
    m_factory->m_builder = nullptr;
}

std::unique_ptr<Hook> Factory::Builder::create(void* target, void* destination) {
    return m_factory->create(target, destination);
}

std::shared_ptr<Hook> Factory::Builder::create_shared(void* target, void* destination) {
    return m_factory->create_shared(target, destination);
}

Factory::Builder::Builder(std::shared_ptr<Factory> factory) 
    : m_factory{std::move(factory)}, m_lock{m_factory->m_mux} {
    m_factory->m_builder = this;
}

Factory::Builder Factory::acquire() {
    return Builder{shared_from_this()};
}

std::unique_ptr<Hook> Factory::create(void* target, void* destination) {
    if (m_builder == nullptr) {
        return nullptr;
    }

    auto hook = std::unique_ptr<Hook>{new Hook{shared_from_this(), (uintptr_t)target, (uintptr_t)destination}};

    if (hook->m_trampoline == 0) {
        return nullptr;
    }

    return hook;
}

std::shared_ptr<Hook> Factory::create_shared(void* target, void* destination) {
    if (m_builder == nullptr) {
        return nullptr;
    }

    auto hook = std::shared_ptr<Hook>{new Hook{shared_from_this(), (uintptr_t)target, (uintptr_t)destination}};

    if (hook->m_trampoline == 0) {
        return nullptr;
    }

    return hook;
}

uintptr_t Factory::allocate(size_t size) {
    return allocate_near({}, size, std::numeric_limits<size_t>::max());
}

uintptr_t Factory::allocate_near(
    const std::vector<uintptr_t>& desired_addresses, size_t size, size_t max_distance) {
    // std::scoped_lock _{m_mux};

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
    SYSTEM_INFO si{};

    GetSystemInfo(&si);

    auto allocation_size = align_up(size, si.dwAllocationGranularity);
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

void Factory::free(uintptr_t address, size_t size) {
    for (auto& allocation : m_allocations) {
        if (allocation->address > address || allocation->address + allocation->size < address) {
            continue;
        }

        // Find the right place for our new freenode.
        FreeNode* prev{};

        for (auto node = allocation->freelist.get(); node != nullptr; prev = node, node = node->next.get()) {
            if (node->start > address) {
                break;
            }
        }

        // Add new freenode.
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

        combine_adjacent_freenodes(*allocation);
        break;
    }
}

void Factory::combine_adjacent_freenodes(MemoryAllocation& allocation) {
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

uintptr_t Factory::allocate_nearby_memory(
    const std::vector<uintptr_t>& desired_addresses, size_t size, size_t max_distance) {
    if (desired_addresses.empty()) {
        return (uintptr_t)VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }

    auto attempt_allocation = [&](uintptr_t p) -> uintptr_t {
        if (!in_range(p, desired_addresses, max_distance)) {
            return 0;
        }

        return (uintptr_t)VirtualAlloc((LPVOID)p, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    };

    SYSTEM_INFO si{};

    GetSystemInfo(&si);

    auto desired_address = desired_addresses[0];
    auto search_start = std::numeric_limits<uintptr_t>::min();
    auto search_end = std::numeric_limits<uintptr_t>::max();

    if (desired_address > max_distance) {
        search_start = desired_address - max_distance;
    }

    if (std::numeric_limits<uintptr_t>::max() - desired_address > max_distance) {
        search_end = desired_address + max_distance;
    }

    search_start = std::max(search_start, (uintptr_t)si.lpMinimumApplicationAddress);
    search_end = std::min(search_end, (uintptr_t)si.lpMaximumApplicationAddress);
    desired_address = align_up(desired_address, si.dwAllocationGranularity);
    MEMORY_BASIC_INFORMATION mbi{};

    // Search backwards from the desired_address.
    for (auto p = desired_address; p > search_start;
         p = align_down((uintptr_t)mbi.BaseAddress - 1, si.dwAllocationGranularity)) {
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

    return 0;
}

bool Factory::in_range(
    uintptr_t address, const std::vector<uintptr_t>& desired_addresses, size_t max_distance) {
    auto is_in_range = true;

    for (auto&& desired_address : desired_addresses) {
        auto delta = (address > desired_address) ? address - desired_address : desired_address - address;
        if (delta > max_distance) {
            is_in_range = false;
            break;
        }
    }

    return is_in_range;
}

Factory::MemoryAllocation::~MemoryAllocation() {
    VirtualFree((LPVOID)address, 0, MEM_RELEASE);
}
}