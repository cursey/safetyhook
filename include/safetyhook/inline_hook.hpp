#pragma once

#include <cstdint>
#include <expected>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

#include "safetyhook/allocator.hpp"

namespace safetyhook {
class InlineHook final {
public:
    struct Error {
        enum Type {
            BAD_ALLOCATION,
            FAILED_TO_DECODE_INSTRUCTION,
            SHORT_JUMP_IN_TRAMPOLINE,
            IP_RELATIVE_INSTRUCTION_OUT_OF_RANGE,
        };

        Type type;

        union Extra {
            Allocator::Error allocator_error;
        };

        Extra extra;

        Error() = default;
        Error(Type type) : type{type} {}
        Error(Allocator::Error allocator_error) : type{Type::BAD_ALLOCATION}, extra{allocator_error} {}
    };

    [[nodiscard]] static std::expected<InlineHook, Error> create(void* target, void* destination);
    [[nodiscard]] static std::expected<InlineHook, Error> create(uintptr_t target, uintptr_t destination);
    [[nodiscard]] static std::expected<InlineHook, Error> create(
        const std::shared_ptr<Allocator>& allocator, void* target, void* destination);
    [[nodiscard]] static std::expected<InlineHook, Error> create(
        const std::shared_ptr<Allocator>& allocator, uintptr_t target, uintptr_t destination);

    InlineHook() = default;
    InlineHook(const InlineHook&) = delete;
    InlineHook(InlineHook&& other) noexcept;
    InlineHook& operator=(const InlineHook&) = delete;
    InlineHook& operator=(InlineHook&& other) noexcept;

    ~InlineHook();

    void reset();

    [[nodiscard]] auto target() const { return m_target; }
    [[nodiscard]] auto destination() const { return m_destination; }
    [[nodiscard]] const auto& trampoline() const { return m_trampoline; }
    explicit operator bool() const { return static_cast<bool>(m_trampoline); }

    template <typename T> [[nodiscard]] T original() const { return reinterpret_cast<T>(m_trampoline.address()); }

    template <typename RetT = void, typename... Args> auto call(Args... args) {
        std::scoped_lock lock{m_mutex};

        if (m_trampoline) {
            return original<RetT (*)(Args...)>()(args...);
        } else {
            return RetT();
        }
    }

    template <typename RetT = void, typename... Args> auto thiscall(Args... args) {
        std::scoped_lock lock{m_mutex};

        if (m_trampoline) {
            return original<RetT(__thiscall*)(Args...)>()(args...);
        } else {
            return RetT();
        }
    }

    template <typename RetT = void, typename... Args> auto stdcall(Args... args) {
        std::scoped_lock lock{m_mutex};

        if (m_trampoline) {
            return original<RetT(__stdcall*)(Args...)>()(args...);
        } else {
            return RetT();
        }
    }

    // These functions are unsafe because they don't lock the mutex. Only use these if you don't care about unhook
    // safety or are worried about the performance cost of locking the mutex.
    template <typename RetT = void, typename... Args> auto unsafe_call(Args... args) {
        return original<RetT (*)(Args...)>()(args...);
    }

    template <typename RetT = void, typename... Args> auto unsafe_thiscall(Args... args) {
        return original<RetT(__thiscall*)(Args...)>()(args...);
    }

    template <typename RetT = void, typename... Args> auto unsafe_stdcall(Args... args) {
        return original<RetT(__stdcall*)(Args...)>()(args...);
    }

private:
    uintptr_t m_target{};
    uintptr_t m_destination{};
    Allocation m_trampoline{};
    size_t m_trampoline_size{};
    std::vector<uint8_t> m_original_bytes{};
    std::recursive_mutex m_mutex{};

    std::expected<void, Error> setup(
        const std::shared_ptr<Allocator>& allocator, uintptr_t target, uintptr_t destination);
    std::expected<void, Error> e9_hook(const std::shared_ptr<Allocator>& allocator);
    std::expected<void, Error> ff_hook(const std::shared_ptr<Allocator>& allocator);
    void destroy();
};
} // namespace safetyhook