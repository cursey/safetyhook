#pragma once

#include <cstdint>
#include <vector>

#include <Windows.h>

namespace safetyhook {
class ThreadFreezer final {
public:
    ThreadFreezer(ThreadFreezer&) = delete;
    ThreadFreezer(ThreadFreezer&&) noexcept = default;
    ThreadFreezer& operator=(ThreadFreezer&) = delete;
    ThreadFreezer& operator=(ThreadFreezer&&) noexcept = default;

    ThreadFreezer();
    ~ThreadFreezer();

    // Goes through all the threads looking for any that are currently on `old_ip`
    // and sets them to `new_ip`.
    void fix_ip(uintptr_t old_ip, uintptr_t new_ip);

private:
    struct FrozenThread {
        uint32_t thread_id{};
        HANDLE handle{};
        CONTEXT ctx{};
    };

    std::vector<FrozenThread> m_frozen_threads{};
};
} // namespace safetyhook