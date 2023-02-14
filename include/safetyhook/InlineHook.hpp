#pragma once

#include <cstdint>
#include <memory>
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

    [[nodiscard]] auto target() const { return m_target; }
    [[nodiscard]] auto destination() const { return m_destination; }
    [[nodiscard]] auto trampoline() const { return m_trampoline; }
    operator bool() const { return m_trampoline != 0; }

    template <typename T> [[nodiscard]] T* original() const { return (T*)m_trampoline; }

    template <typename RetT = void, typename... Args> auto call(Args... args) {
        if (m_trampoline != 0) {
            return ((RetT(*)(Args...))m_trampoline)(args...);
        } else {
            return RetT{};
        }
    }

    template <typename RetT = void, typename... Args> auto thiscall(Args... args) {
        if (m_trampoline != 0) {
            return ((RetT(__thiscall*)(Args...))m_trampoline)(args...);
        } else {
            return RetT{};
        }
    }

    template <typename RetT = void, typename... Args> auto stdcall(Args... args) {
        if (m_trampoline != 0) {
            return ((RetT(__stdcall*)(Args...))m_trampoline)(args...);
        } else {
            return RetT{};
        }
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

    InlineHook(std::shared_ptr<Factory> factory, uintptr_t target, uintptr_t destination);

    void e9_hook();
    void ff_hook();
    void destroy();
};
} // namespace safetyhook