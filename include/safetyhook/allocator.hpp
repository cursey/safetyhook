#pragma once

#include <cstdint>
#include <expected>
#include <memory>
#include <mutex>
#include <vector>

namespace safetyhook {
class Allocator;

class Allocation final {
public:
    Allocation() = default;
    Allocation(const Allocation&) = delete;
    Allocation(Allocation&& other) noexcept;
    Allocation& operator=(const Allocation&) = delete;
    Allocation& operator=(Allocation&& other) noexcept;
    ~Allocation();

    void free();

    [[nodiscard]] uintptr_t address() const noexcept { return m_address; }
    [[nodiscard]] size_t size() const noexcept { return m_size; }
    explicit operator bool() const noexcept { return m_address != 0 && m_size != 0; }

protected:
    friend Allocator;

    Allocation(std::shared_ptr<Allocator> allocator, uintptr_t address, size_t size) noexcept;

private:
    std::shared_ptr<Allocator> m_allocator{};
    uintptr_t m_address{};
    size_t m_size{};
};

class Allocator final : public std::enable_shared_from_this<Allocator> {
public:
    [[nodiscard]] static std::shared_ptr<Allocator> global();
    [[nodiscard]] static std::shared_ptr<Allocator> create();

    Allocator(const Allocator&) = delete;
    Allocator(Allocator&&) noexcept = delete;
    Allocator& operator=(const Allocator&) = delete;
    Allocator& operator=(Allocator&&) noexcept = delete;
    ~Allocator() = default;

    enum class Error {
        BAD_VIRTUAL_ALLOC,
        NO_MEMORY_IN_RANGE,
    };

    [[nodiscard]] std::expected<Allocation, Error> allocate(size_t size);
    [[nodiscard]] std::expected<Allocation, Error> allocate_near(
        const std::vector<uintptr_t>& desired_addresses, size_t size, size_t max_distance = 0x7FFF'FFFF);

protected:
    friend Allocation;

    void free(uintptr_t address, size_t size);

private:
    struct FreeNode {
        std::unique_ptr<FreeNode> next{};
        uintptr_t start{};
        uintptr_t end{};
    };

    struct Memory {
        uintptr_t address{};
        size_t size{};
        std::unique_ptr<FreeNode> freelist{};

        ~Memory();
    };

    std::vector<std::unique_ptr<Memory>> m_memory{};
    std::mutex m_mutex{};

    Allocator() = default;

    [[nodiscard]] std::expected<Allocation, Error> internal_allocate_near(
        const std::vector<uintptr_t>& desired_addresses, size_t size, size_t max_distance = 0x7FFF'FFFF);
    void internal_free(uintptr_t address, size_t size);

    void combine_adjacent_freenodes(Memory& memory);
    [[nodiscard]] std::expected<uintptr_t, Error> allocate_nearby_memory(
        const std::vector<uintptr_t>& desired_addresses, size_t size, size_t max_distance);
    [[nodiscard]] bool in_range(
        uintptr_t address, const std::vector<uintptr_t>& desired_addresses, size_t max_distance);
};
} // namespace safetyhook