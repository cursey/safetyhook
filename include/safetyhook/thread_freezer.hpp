/// @file safetyhook/thread_freezer.hpp
/// @brief A class for freezing all threads in the process.

#pragma once

#include <cstdint>
#include <vector>

#include <Windows.h>

namespace safetyhook {

/// @brief A class for freezing all threads in the process.
class ThreadFreezer final {
public:
    ThreadFreezer(ThreadFreezer&) = delete;
    ThreadFreezer(ThreadFreezer&&) noexcept = default;
    ThreadFreezer& operator=(ThreadFreezer&) = delete;
    ThreadFreezer& operator=(ThreadFreezer&&) noexcept = default;

    /// @brief Constructs a new ThreadFreezer object.
    /// @note This freezes all threads in the process except the current thread.
    ThreadFreezer();

    /// @brief Destructs the ThreadFreezer object.
    /// @note This unfreezes all threads in the process.
    ~ThreadFreezer();

    /// @brief Fixes any threads that are currently on `old_ip` and sets them to `new_ip`.
    /// @param old_ip The old instruction pointer.
    /// @param new_ip The new instruction pointer.
    void fix_ip(uintptr_t old_ip, uintptr_t new_ip);

private:
    struct FrozenThread {
        uint32_t thread_id{};
        HANDLE handle{};
        CONTEXT ctx{};
    };

    // Custom allocator for `m_frozen_threads` that will work while threads are being frozen. This is necessary because
    // `new` can deadlock while freezing threads.
    template <class T> struct HeapAllocator {
        using value_type = T;

        HeapAllocator() = default;
        template <class U> constexpr HeapAllocator(const HeapAllocator<U>&) noexcept {}
        [[nodiscard]] T* allocate(size_t n) { return static_cast<T*>(HeapAlloc(GetProcessHeap(), 0, n * sizeof(T))); }
        void deallocate(T* p, size_t) noexcept { HeapFree(GetProcessHeap(), 0, p); }
    };

    std::vector<FrozenThread, HeapAllocator<FrozenThread>> m_frozen_threads{};
};
} // namespace safetyhook