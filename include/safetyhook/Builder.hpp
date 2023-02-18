#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
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
    bool transact();

private:
    friend Factory;
    friend InlineHook;
    friend MidHook;

    struct InlineHookInfo {
        InlineHook* hook{};
        uintptr_t target{};
        uintptr_t destination{};
    };

    struct MidHookInfo {
        MidHook* hook{};
        uintptr_t target{};
        MidHookFn destination{};
    };

    std::shared_ptr<Factory> m_factory{};
    std::scoped_lock<std::recursive_mutex> m_factory_lock;
    std::unique_ptr<ThreadFreezer> m_threads{};
    std::shared_ptr<std::vector<InlineHookInfo>> m_inline_hooks{};
    std::shared_ptr<std::vector<MidHookInfo>> m_mid_hooks{};

    explicit Builder(std::shared_ptr<Factory> f);

    void fix_ip(uintptr_t old_ip, uintptr_t new_ip);
    [[nodiscard]] uintptr_t allocate(size_t size);
    [[nodiscard]] uintptr_t allocate_near(
        const std::vector<uintptr_t>& desired_addresses, size_t size, size_t max_distance = 0x7FFF'FFFF);
    void free(uintptr_t address, size_t size);
    void notify_hook_moved(InlineHook* from, InlineHook* to);
    void notify_hook_moved(MidHook* from, MidHook* to);
};
} // namespace safetyhook