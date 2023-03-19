/// @file safetyhook/mid_hook.hpp
/// @brief Mid function hooking class.

#pragma once

#include <cstdint>
#include <memory>

#include <safetyhook/allocator.hpp>
#include <safetyhook/context.hpp>
#include <safetyhook/inline_hook.hpp>

namespace safetyhook {

/// @brief A MidHook destination function.
using MidHookFn = void (*)(Context& ctx);

/// @brief A mid function hook.
class MidHook final {
public:
    /// @brief Error type for MidHook.
    struct Error {
        /// @brief The type of error.
        enum : uint8_t { BAD_ALLOCATION, BAD_INLINE_HOOK } type;

        /// @brief Extra error information.
        union {
            Allocator::Error allocator_error;    ///< Allocator error information.
            InlineHook::Error inline_hook_error; ///< InlineHook error information.
        };

        /// @brief Create a BAD_ALLOCATION error.
        /// @param err The Allocator::Error that failed.
        /// @return The new BAD_ALLOCATION error.
        [[nodiscard]] static Error bad_allocation(Allocator::Error err) {
            return {.type = BAD_ALLOCATION, .allocator_error = err};
        }

        /// @brief Create a BAD_INLINE_HOOK error.
        /// @param err The InlineHook::Error that failed.
        /// @return The new BAD_INLINE_HOOK error.
        [[nodiscard]] static Error bad_inline_hook(InlineHook::Error err) {
            return {.type = BAD_INLINE_HOOK, .inline_hook_error = err};
        }
    };

    /// @brief Creates a new MidHook object.
    /// @param target The address of the function to hook.
    /// @param destination The destination function.
    /// @return The MidHook object or a MidHook::Error if an error occurred.
    /// @note This will use the default global Allocator.
    /// @note If you don't care about error handling, use the easy API (safetyhook::create_mid).
    [[nodiscard]] static std::expected<MidHook, Error> create(void* target, MidHookFn destination);

    /// @brief Creates a new MidHook object.
    /// @param target The address of the function to hook.
    /// @param destination The destination function.
    /// @return The MidHook object or a MidHook::Error if an error occurred.
    /// @note This will use the default global Allocator.
    /// @note If you don't care about error handling, use the easy API (safetyhook::create_mid).
    [[nodiscard]] static std::expected<MidHook, Error> create(uintptr_t target, MidHookFn destination);

    /// @brief Creates a new MidHook object with a given Allocator.
    /// @param allocator The Allocator to use.
    /// @param target The address of the function to hook.
    /// @param destination The destination function.
    /// @return The MidHook object or a MidHook::Error if an error occurred.
    /// @note If you don't care about error handling, use the easy API (safetyhook::create_mid).
    [[nodiscard]] static std::expected<MidHook, Error> create(
        const std::shared_ptr<Allocator>& allocator, void* target, MidHookFn destination);

    /// @brief Creates a new MidHook object with a given Allocator.
    /// @param allocator The Allocator to use.
    /// @param target The address of the function to hook.
    /// @param destination The destination function.
    /// @return The MidHook object or a MidHook::Error if an error occurred.
    /// @note If you don't care about error handling, use the easy API (safetyhook::create_mid).
    [[nodiscard]] static std::expected<MidHook, Error> create(
        const std::shared_ptr<Allocator>& allocator, uintptr_t target, MidHookFn destination);

    MidHook() = default;
    MidHook(const MidHook&) = delete;
    MidHook(MidHook&& other) noexcept;
    MidHook& operator=(const MidHook&) = delete;
    MidHook& operator=(MidHook&& other) noexcept;
    ~MidHook() = default;

    /// @brief Reset the hook.
    /// @details This will remove the hook and free the stub.
    /// @note This is called automatically in the destructor.
    void reset();

    /// @brief Get the target address.
    /// @return The target address.
    [[nodiscard]] uintptr_t target() const { return m_target; }

    /// @brief Get the destination function.
    /// @return The destination function.
    [[nodiscard]] MidHookFn destination() const { return m_destination; }

    /// @brief Tests if the hook is valid.
    /// @return true if the hook is valid, false otherwise.
    explicit operator bool() const { return static_cast<bool>(m_stub); }

private:
    InlineHook m_hook{};
    uintptr_t m_target{};
    Allocation m_stub{};
    MidHookFn m_destination{};

    std::expected<void, Error> setup(
        const std::shared_ptr<Allocator>& allocator, uintptr_t target, MidHookFn destination);
};
} // namespace safetyhook