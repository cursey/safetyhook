#include <algorithm>
#include <functional>
#include <limits>

#define NOMINMAX
#include <Windows.h>

#include <safetyhook/allocator.hpp>

namespace safetyhook {
template <typename T> constexpr T align_up(T address, size_t align) {
    const auto unaligned_address = (uintptr_t)address;
    const auto aligned_address = (unaligned_address + align - 1) & ~(align - 1);
    return (T)aligned_address;
}

template <typename T> constexpr T align_down(T address, size_t align) {
    const auto unaligned_address = (uintptr_t)address;
    const auto aligned_address = unaligned_address & ~(align - 1);
    return (T)aligned_address;
}

Allocation::Allocation(Allocation&& other) noexcept {
    *this = std::move(other);
}

Allocation& Allocation::operator=(Allocation&& other) noexcept {
    if (this != &other) {
        free();

        m_allocator = std::move(other.m_allocator);
        m_address = other.m_address;
        m_size = other.m_size;

        other.m_address = nullptr;
        other.m_size = 0;
    }

    return *this;
}

Allocation::~Allocation() {
    free();
}

void Allocation::free() {
    if (m_allocator && m_address != nullptr && m_size != 0) {
        m_allocator->free(m_address, m_size);
        m_address = nullptr;
        m_size = 0;
        m_allocator.reset();
    }
}

Allocation::Allocation(std::shared_ptr<Allocator> allocator, uint8_t* address, size_t size) noexcept
    : m_allocator{std::move(allocator)}, m_address{address}, m_size{size} {
}

std::shared_ptr<Allocator> Allocator::global() {
    static std::weak_ptr<Allocator> global_allocator{};
    static std::mutex global_allocator_mutex{};

    std::scoped_lock lock{global_allocator_mutex};

    if (auto allocator = global_allocator.lock()) {
        return allocator;
    }

    auto allocator = Allocator::create();

    global_allocator = allocator;

    return allocator;
}

std::shared_ptr<Allocator> Allocator::create() {
    return std::shared_ptr<Allocator>{new Allocator{}};
}

std::expected<Allocation, Allocator::Error> Allocator::allocate(size_t size) {
    return allocate_near({}, size, std::numeric_limits<size_t>::max());
}

std::expected<Allocation, Allocator::Error> Allocator::allocate_near(
    const std::vector<uint8_t*>& desired_addresses, size_t size, size_t max_distance) {
    std::scoped_lock lock{m_mutex};
    return internal_allocate_near(desired_addresses, size, max_distance);
}

void Allocator::free(uint8_t* address, size_t size) {
    std::scoped_lock lock{m_mutex};
    return internal_free(address, size);
}

std::expected<Allocation, Allocator::Error> Allocator::internal_allocate_near(
    const std::vector<uint8_t*>& desired_addresses, size_t size, size_t max_distance) {
    // First search through our list of allocations for a free block that is large
    // enough.
    for (const auto& allocation : m_memory) {
        if (allocation->size < size) {
            continue;
        }

        for (auto node = allocation->freelist.get(); node != nullptr; node = node->next.get()) {
            // Enough room?
            if (static_cast<size_t>(node->end - node->start) < size) {
                continue;
            }

            const auto address = node->start;

            // Close enough?
            if (!in_range(address, desired_addresses, max_distance)) {
                continue;
            }

            node->start += size;

            return Allocation{shared_from_this(), address, size};
        }
    }

    // If we didn't find a free block, we need to allocate a new one.
    SYSTEM_INFO si{};

    GetSystemInfo(&si);

    const auto allocation_size = align_up(size, si.dwAllocationGranularity);
    const auto allocation_address = allocate_nearby_memory(desired_addresses, allocation_size, max_distance);

    if (!allocation_address) {
        return std::unexpected{allocation_address.error()};
    }

    const auto& allocation = m_memory.emplace_back(new Memory);

    allocation->address = *allocation_address;
    allocation->size = allocation_size;
    allocation->freelist = std::make_unique<FreeNode>();
    allocation->freelist->start = *allocation_address + size;
    allocation->freelist->end = *allocation_address + allocation_size;

    return Allocation{shared_from_this(), *allocation_address, size};
}

void Allocator::internal_free(uint8_t* address, size_t size) {
    for (const auto& allocation : m_memory) {
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

void Allocator::combine_adjacent_freenodes(Memory& memory) {
    for (auto prev = memory.freelist.get(), node = prev; node != nullptr; node = node->next.get()) {
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

std::expected<uint8_t*, Allocator::Error> Allocator::allocate_nearby_memory(
    const std::vector<uint8_t*>& desired_addresses, size_t size, size_t max_distance) {
    if (desired_addresses.empty()) {
        if (const auto result = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            result != nullptr) {
            return static_cast<uint8_t*>(result);
        }

        return std::unexpected{Error::BAD_VIRTUAL_ALLOC};
    }

    auto attempt_allocation = [&](uint8_t* p) -> uint8_t* {
        if (!in_range(p, desired_addresses, max_distance)) {
            return nullptr;
        }

        return static_cast<uint8_t*>(VirtualAlloc(p, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    };

    SYSTEM_INFO si{};

    GetSystemInfo(&si);

    auto desired_address = desired_addresses[0];
    auto search_start = reinterpret_cast<uint8_t*>(std::numeric_limits<uintptr_t>::min());
    auto search_end = reinterpret_cast<uint8_t*>(std::numeric_limits<uintptr_t>::max());

    if (static_cast<size_t>(desired_address - search_start) > max_distance) {
        search_start = desired_address - max_distance;
    }

    if (static_cast<size_t>(search_end - desired_address) > max_distance) {
        search_end = desired_address + max_distance;
    }

    search_start = std::max(search_start, static_cast<uint8_t*>(si.lpMinimumApplicationAddress));
    search_end = std::min(search_end, static_cast<uint8_t*>(si.lpMaximumApplicationAddress));
    desired_address = align_up(desired_address, si.dwAllocationGranularity);
    MEMORY_BASIC_INFORMATION mbi{};

    // Search backwards from the desired_address.
    for (auto p = desired_address; p > search_start && in_range(p, desired_addresses, max_distance);
         p = align_down(static_cast<uint8_t*>(mbi.AllocationBase) - 1, si.dwAllocationGranularity)) {
        if (VirtualQuery(p, &mbi, sizeof(mbi)) == 0) {
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
    for (auto p = desired_address; p < search_end && in_range(p, desired_addresses, max_distance);
         p += mbi.RegionSize) {
        if (VirtualQuery(p, &mbi, sizeof(mbi)) == 0) {
            break;
        }

        if (mbi.State != MEM_FREE) {
            continue;
        }

        if (auto allocation_address = attempt_allocation(p); allocation_address != nullptr) {
            return allocation_address;
        }
    }

    return std::unexpected{Error::NO_MEMORY_IN_RANGE};
}

bool Allocator::in_range(uint8_t* address, const std::vector<uint8_t*>& desired_addresses, size_t max_distance) {
    return std::ranges::all_of(desired_addresses, [&](const auto& desired_address) {
        const size_t delta = (address > desired_address) ? address - desired_address : desired_address - address;
        return delta <= max_distance;
    });
}

Allocator::Memory::~Memory() {
    VirtualFree(address, 0, MEM_RELEASE);
}
} // namespace safetyhook