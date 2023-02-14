#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include "safetyhook/Context.hpp"

namespace safetyhook {
class InlineHook;
class MidHook;
class Factory;
class ThreadFreezer;

class Builder final {
public:
    Builder(const Builder&) = delete;
    Builder(Builder&&) noexcept = delete;
    Builder& operator=(const Builder&) = delete;
    Builder& operator=(Builder&&) noexcept = delete;

    ~Builder();

    [[nodiscard]] InlineHook create_inline(void* target, void* destination);
    [[nodiscard]] MidHook create_mid(void* target, MidHookFn destination);

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
} // namespace safetyhook