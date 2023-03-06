/// @file safetyhook/inline_hook.hpp
/// @brief Inline hooking class.

#pragma once

#include <cstdint>
#include <expected>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

#include "safetyhook/allocator.hpp"

namespace safetyhook {
/// @brief An inline hook.
class InlineHook final {
public:
    /// @brief Error type for InlineHook.
    struct Error {
        /// @brief The type of error.
        enum Type {
            BAD_ALLOCATION,                       ///< An error occurred when allocating memory.
            FAILED_TO_DECODE_INSTRUCTION,         ///< Failed to decode an instruction.
            SHORT_JUMP_IN_TRAMPOLINE,             ///< The trampoline contains a short jump.
            IP_RELATIVE_INSTRUCTION_OUT_OF_RANGE, ///< An IP-relative instruction is out of range.
        };

        /// @brief The type of error.
        Type type;

        /// @brief Extra information about the error.
        union Extra {
            Allocator::Error allocator_error; ///< Allocator error information.
        };

        /// @brief Extra information about the error.
        Extra extra;

        Error() = default;

        /// @brief Constructs a new Error object with the given type.
        /// @param type The type of the error.
        Error(Type type) : type{type} {}

        /// @brief Creates a BAD_ALLOCATION error.
        /// @param allocator_error The Allocator::Error responsible.
        Error(Allocator::Error allocator_error) : type{Type::BAD_ALLOCATION}, extra{allocator_error} {}
    };

    /// @brief Create an inline hook.
    /// @param target The address of the function to hook.
    /// @param destination The destination address.
    /// @return The InlineHook or an InlineHook::Error if an error occured.
    /// @note This will use the default global Allocator.
    /// @note If you don't care about error handling, use the easy API (safetyhook::create_inline).
    [[nodiscard]] static std::expected<InlineHook, Error> create(void* target, void* destination);

    /// @brief Create an inline hook.
    /// @param target The address of the function to hook.
    /// @param destination The destination address.
    /// @return The InlineHook or an InlineHook::Error if an error occured.
    /// @note This will use the default global Allocator.
    /// @note If you don't care about error handling, use the easy API (safetyhook::create_inline).
    [[nodiscard]] static std::expected<InlineHook, Error> create(uintptr_t target, uintptr_t destination);

    /// @brief Create an inline hook with a given Allocator.
    /// @param allocator The allocator to use.
    /// @param target The address of the function to hook.
    /// @param destination The destination address.
    /// @return The InlineHook or an InlineHook::Error if an error occured.
    /// @note If you don't care about error handling, use the easy API (safetyhook::create_inline).
    [[nodiscard]] static std::expected<InlineHook, Error> create(
        const std::shared_ptr<Allocator>& allocator, void* target, void* destination);

    /// @brief Create an inline hook with a given Allocator.
    /// @param allocator The allocator to use.
    /// @param target The address of the function to hook.
    /// @param destination The destination address.
    /// @return The InlineHook or an InlineHook::Error if an error occured.
    /// @note If you don't care about error handling, use the easy API (safetyhook::create_inline).
    [[nodiscard]] static std::expected<InlineHook, Error> create(
        const std::shared_ptr<Allocator>& allocator, uintptr_t target, uintptr_t destination);

    InlineHook() = default;
    InlineHook(const InlineHook&) = delete;
    InlineHook(InlineHook&& other) noexcept;
    InlineHook& operator=(const InlineHook&) = delete;
    InlineHook& operator=(InlineHook&& other) noexcept;
    ~InlineHook();

    /// @brief Reset the hook.
    /// @details This will restore the original function and remove the hook.
    /// @note This is called automatically in the destructor.
    void reset();

    /// @brief Get the target address.
    /// @return The target address.
    [[nodiscard]] uintptr_t target() const { return m_target; }

    /// @brief Get the destination address.
    /// @return The destination address.
    [[nodiscard]] size_t destination() const { return m_destination; }

    /// @brief Get the trampoline Allocation.
    /// @return The trampoline Allocation.
    [[nodiscard]] const Allocation& trampoline() const { return m_trampoline; }

    /// @brief Tests if the hook is valid.
    /// @return True if the hook is valid, false otherwise.
    explicit operator bool() const { return static_cast<bool>(m_trampoline); }

    /// @brief Returns the address of the trampoline to call the original function.
    /// @tparam T The type of the function pointer.
    /// @return The address of the trampoline to call the original function.
    template <typename T> [[nodiscard]] T original() const { return reinterpret_cast<T>(m_trampoline.address()); }

    /// @brief Calls the original function.
    /// @tparam RetT The return type of the function.
    /// @tparam ...Args The argument types of the function.
    /// @param ...args The arguments to pass to the function.
    /// @return The result of calling the original function.
    /// @note This function will use the default calling convention set by your compiler.
    template <typename RetT = void, typename... Args> RetT call(Args... args) {
        std::scoped_lock lock{m_mutex};

        if (m_trampoline) {
            return original<RetT (*)(Args...)>()(args...);
        } else {
            return RetT();
        }
    }

    /// @brief Calls the original function.
    /// @tparam RetT The return type of the function.
    /// @tparam ...Args The argument types of the function.
    /// @param ...args The arguments to pass to the function.
    /// @return The result of calling the original function.
    /// @note This function will use the __cdecl calling convention.
    template <typename RetT = void, typename... Args> RetT ccall(Args... args) {
        std::scoped_lock lock{m_mutex};

        if (m_trampoline) {
            return original<RetT(__cdecl*)(Args...)>()(args...);
        } else {
            return RetT();
        }
    }

    /// @brief Calls the original function.
    /// @tparam RetT The return type of the function.
    /// @tparam ...Args The argument types of the function.
    /// @param ...args The arguments to pass to the function.
    /// @return The result of calling the original function.
    /// @note This function will use the __thiscall calling convention.
    template <typename RetT = void, typename... Args> RetT thiscall(Args... args) {
        std::scoped_lock lock{m_mutex};

        if (m_trampoline) {
            return original<RetT(__thiscall*)(Args...)>()(args...);
        } else {
            return RetT();
        }
    }

    /// @brief Calls the original function.
    /// @tparam RetT The return type of the function.
    /// @tparam ...Args The argument types of the function.
    /// @param ...args The arguments to pass to the function.
    /// @return The result of calling the original function.
    /// @note This function will use the __stdcall calling convention.
    template <typename RetT = void, typename... Args> RetT stdcall(Args... args) {
        std::scoped_lock lock{m_mutex};

        if (m_trampoline) {
            return original<RetT(__stdcall*)(Args...)>()(args...);
        } else {
            return RetT();
        }
    }

    /// @brief Calls the original function.
    /// @tparam RetT The return type of the function.
    /// @tparam ...Args The argument types of the function.
    /// @param ...args The arguments to pass to the function.
    /// @return The result of calling the original function.
    /// @note This function will use the default calling convention set by your compiler.
    /// @note This function is unsafe because it doesn't lock the mutex. Only use this if you don't care about unhook
    // safety or are worried about the performance cost of locking the mutex.
    template <typename RetT = void, typename... Args> RetT unsafe_call(Args... args) {
        return original<RetT (*)(Args...)>()(args...);
    }

    /// @brief Calls the original function.
    /// @tparam RetT The return type of the function.
    /// @tparam ...Args The argument types of the function.
    /// @param ...args The arguments to pass to the function.
    /// @return The result of calling the original function.
    /// @note This function will use the __cdecl calling convention.
    /// @note This function is unsafe because it doesn't lock the mutex. Only use this if you don't care about unhook
    // safety or are worried about the performance cost of locking the mutex.
    template <typename RetT = void, typename... Args> RetT unsafe_ccall(Args... args) {
        return original<RetT(__cdecl*)(Args...)>()(args...);
    }

    /// @brief Calls the original function.
    /// @tparam RetT The return type of the function.
    /// @tparam ...Args The argument types of the function.
    /// @param ...args The arguments to pass to the function.
    /// @return The result of calling the original function.
    /// @note This function will use the __thiscall calling convention.
    /// @note This function is unsafe because it doesn't lock the mutex. Only use this if you don't care about unhook
    // safety or are worried about the performance cost of locking the mutex.
    template <typename RetT = void, typename... Args> RetT unsafe_thiscall(Args... args) {
        return original<RetT(__thiscall*)(Args...)>()(args...);
    }

    /// @brief Calls the original function.
    /// @tparam RetT The return type of the function.
    /// @tparam ...Args The argument types of the function.
    /// @param ...args The arguments to pass to the function.
    /// @return The result of calling the original function.
    /// @note This function will use the __stdcall calling convention.
    /// @note This function is unsafe because it doesn't lock the mutex. Only use this if you don't care about unhook
    // safety or are worried about the performance cost of locking the mutex.
    template <typename RetT = void, typename... Args> RetT unsafe_stdcall(Args... args) {
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