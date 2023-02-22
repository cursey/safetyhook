#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

namespace safetyhook {
class Factory;
class Builder;

class InlineHook final {
public:
    InlineHook() = default;
    InlineHook(const InlineHook&) = delete;
    InlineHook(InlineHook&& other) noexcept;
    InlineHook& operator=(const InlineHook&) = delete;
    InlineHook& operator=(InlineHook&& other) noexcept;

    ~InlineHook();

    void reset();

    [[nodiscard]] auto target() const { return m_target; }
    [[nodiscard]] auto destination() const { return m_destination; }
    [[nodiscard]] auto trampoline() const { return m_trampoline; }
    operator bool() const { return m_trampoline != 0; }

    template <typename T> [[nodiscard]] T* original() const { return (T*)m_trampoline; }

    template <typename RetT = void, typename... Args> auto call(Args... args) {
        std::scoped_lock lock{m_mutex};

        if (m_trampoline != 0) {
            return ((RetT(*)(Args...))m_trampoline)(args...);
        } else {
            return RetT();
        }
    }

    template <typename RetT = void, typename... Args> auto thiscall(Args... args) {
        std::scoped_lock lock{m_mutex};

        if (m_trampoline != 0) {
            return ((RetT(__thiscall*)(Args...))m_trampoline)(args...);
        } else {
            return RetT();
        }
    }

    template <typename RetT = void, typename... Args> auto stdcall(Args... args) {
        std::scoped_lock lock{m_mutex};

        if (m_trampoline != 0) {
            return ((RetT(__stdcall*)(Args...))m_trampoline)(args...);
        } else {
            return RetT();
        }
    }

    // These functions are unsafe because they don't lock the mutex. Only use these if you don't care about unhook
    // safety or are worried about the performance cost of locking the mutex.
    template <typename RetT = void, typename... Args> auto unsafe_call(Args... args) {
        return ((RetT(*)(Args...))m_trampoline)(args...);
    }

    template <typename RetT = void, typename... Args> auto unsafe_thiscall(Args... args) {
        return ((RetT(__thiscall*)(Args...))m_trampoline)(args...);
    }

    template <typename RetT = void, typename... Args> auto unsafe_stdcall(Args... args) {
        return ((RetT(__stdcall*)(Args...))m_trampoline)(args...);
    }

private:
    friend Builder;

    std::shared_ptr<Factory> m_factory;
    uintptr_t m_target{};
    uintptr_t m_destination{};
    uintptr_t m_trampoline{};
    size_t m_trampoline_size{};
    size_t m_trampoline_allocation_size{};
    std::vector<uint8_t> m_original_bytes{};
    std::recursive_mutex m_mutex{};

    InlineHook(std::shared_ptr<Factory> factory, uintptr_t target, uintptr_t destination);

    void e9_hook();
    void ff_hook();
    void destroy();
};
} // namespace safetyhook