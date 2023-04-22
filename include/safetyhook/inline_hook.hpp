/// @file safetyhook/inline_hook.hpp
/// @brief Inline hooking class.

#pragma once

#include <cstdint>
#include <expected>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

#include <safetyhook/allocator.hpp>

namespace safetyhook {
/// @brief An inline hook.
class InlineHook final {
public:
    /// @brief Error type for InlineHook.
    struct Error {
        /// @brief The type of error.
        enum : uint8_t {
            BAD_ALLOCATION,                        ///< An error occurred when allocating memory.
            FAILED_TO_DECODE_INSTRUCTION,          ///< Failed to decode an instruction.
            SHORT_JUMP_IN_TRAMPOLINE,              ///< The trampoline contains a short jump.
            IP_RELATIVE_INSTRUCTION_OUT_OF_RANGE,  ///< An IP-relative instruction is out of range.
            UNSUPPORTED_INSTRUCTION_IN_TRAMPOLINE, ///< An unsupported instruction was found in the trampoline.
        } type;

        /// @brief Extra information about the error.
        union {
            Allocator::Error allocator_error; ///< Allocator error information.
            uint8_t* ip;                      ///< IP of the problematic instruction.
        };

        /// @brief Create a BAD_ALLOCATION error.
        /// @param err The Allocator::Error that failed.
        /// @return The new BAD_ALLOCATION error.
        [[nodiscard]] static Error bad_allocation(Allocator::Error err) {
            return {.type = BAD_ALLOCATION, .allocator_error = err};
        }

        /// @brief Create a FAILED_TO_DECODE_INSTRUCTION error.
        /// @param ip The IP of the problematic instruction.
        /// @return The new FAILED_TO_DECODE_INSTRUCTION error.
        [[nodiscard]] static Error failed_to_decode_instruction(uint8_t* ip) {
            return {.type = FAILED_TO_DECODE_INSTRUCTION, .ip = ip};
        }

        /// @brief Create a SHORT_JUMP_IN_TRAMPOLINE error.
        /// @param ip The IP of the problematic instruction.
        /// @return The new SHORT_JUMP_IN_TRAMPOLINE error.
        [[nodiscard]] static Error short_jump_in_trampoline(uint8_t* ip) {
            return {.type = SHORT_JUMP_IN_TRAMPOLINE, .ip = ip};
        }

        /// @brief Create a IP_RELATIVE_INSTRUCTION_OUT_OF_RANGE error.
        /// @param ip The IP of the problematic instruction.
        /// @return The new IP_RELATIVE_INSTRUCTION_OUT_OF_RANGE error.
        [[nodiscard]] static Error ip_relative_instruction_out_of_range(uint8_t* ip) {
            return {.type = IP_RELATIVE_INSTRUCTION_OUT_OF_RANGE, .ip = ip};
        }

        /// @brief Create a UNSUPPORTED_INSTRUCTION_IN_TRAMPOLINE error.
        /// @param ip The IP of the problematic instruction.
        /// @return The new UNSUPPORTED_INSTRUCTION_IN_TRAMPOLINE error.
        [[nodiscard]] static Error unsupported_instruction_in_trampoline(uint8_t* ip) {
            return {.type = UNSUPPORTED_INSTRUCTION_IN_TRAMPOLINE, .ip = ip};
        }
    };

    /// @brief Create an inline hook.
    /// @param target The address of the function to hook.
    /// @param destination The destination address.
    /// @return The InlineHook or an InlineHook::Error if an error occurred.
    /// @note This will use the default global Allocator.
    /// @note If you don't care about error handling, use the easy API (safetyhook::create_inline).
    [[nodiscard]] static std::expected<InlineHook, Error> create(void* target, void* destination);

    /// @brief Create an inline hook.
    /// @param target The address of the function to hook.
    /// @param destination The destination address.
    /// @return The InlineHook or an InlineHook::Error if an error occurred.
    /// @note This will use the default global Allocator.
    /// @note If you don't care about error handling, use the easy API (safetyhook::create_inline).
    [[nodiscard]] static std::expected<InlineHook, Error> create(uintptr_t target, uintptr_t destination);

    /// @brief Create an inline hook with a given Allocator.
    /// @param allocator The allocator to use.
    /// @param target The address of the function to hook.
    /// @param destination The destination address.
    /// @return The InlineHook or an InlineHook::Error if an error occurred.
    /// @note If you don't care about error handling, use the easy API (safetyhook::create_inline).
    [[nodiscard]] static std::expected<InlineHook, Error> create(
        const std::shared_ptr<Allocator>& allocator, void* target, void* destination);

    /// @brief Create an inline hook with a given Allocator.
    /// @param allocator The allocator to use.
    /// @param target The address of the function to hook.
    /// @param destination The destination address.
    /// @return The InlineHook or an InlineHook::Error if an error occurred.
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

    /// @brief Get a pointer to the target.
    /// @return A pointer to the target.
    [[nodiscard]] uint8_t* target() const { return m_target; }

    /// @brief Get the target address.
    /// @return The target address.
    [[nodiscard]] uintptr_t target_address() const { return reinterpret_cast<uintptr_t>(m_target); }

    /// @brief Get a pointer ot the destination.
    /// @return A pointer to the destination.
    [[nodiscard]] uint8_t* destination() const { return m_destination; }

    /// @brief Get the destination address.
    /// @return The destination address.
    [[nodiscard]] uintptr_t destination_address() const { return reinterpret_cast<uintptr_t>(m_destination); }

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
        return m_trampoline ? original<RetT (*)(Args...)>()(args...) : RetT();
    }

    /// @brief Calls the original function.
    /// @tparam RetT The return type of the function.
    /// @tparam ...Args The argument types of the function.
    /// @param ...args The arguments to pass to the function.
    /// @return The result of calling the original function.
    /// @note This function will use the __cdecl calling convention.
    template <typename RetT = void, typename... Args> RetT ccall(Args... args) {
        std::scoped_lock lock{m_mutex};
        return m_trampoline ? original<RetT(__cdecl*)(Args...)>()(args...) : RetT();
    }

    /// @brief Calls the original function.
    /// @tparam RetT The return type of the function.
    /// @tparam ...Args The argument types of the function.
    /// @param ...args The arguments to pass to the function.
    /// @return The result of calling the original function.
    /// @note This function will use the __thiscall calling convention.
    template <typename RetT = void, typename... Args> RetT thiscall(Args... args) {
        std::scoped_lock lock{m_mutex};
        return m_trampoline ? original<RetT(__thiscall*)(Args...)>()(args...) : RetT();
    }

    /// @brief Calls the original function.
    /// @tparam RetT The return type of the function.
    /// @tparam ...Args The argument types of the function.
    /// @param ...args The arguments to pass to the function.
    /// @return The result of calling the original function.
    /// @note This function will use the __stdcall calling convention.
    template <typename RetT = void, typename... Args> RetT stdcall(Args... args) {
        std::scoped_lock lock{m_mutex};
        return m_trampoline ? original<RetT(__stdcall*)(Args...)>()(args...) : RetT();
    }

    /// @brief Calls the original function.
    /// @tparam RetT The return type of the function.
    /// @tparam ...Args The argument types of the function.
    /// @param ...args The arguments to pass to the function.
    /// @return The result of calling the original function.
    /// @note This function will use the __fastcall calling convention.
    template <typename RetT = void, typename... Args> RetT fastcall(Args... args) {
        std::scoped_lock lock{m_mutex};
        return m_trampoline ? original<RetT(__fastcall*)(Args...)>()(args...) : RetT();
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

    /// @brief Calls the original function.
    /// @tparam RetT The return type of the function.
    /// @tparam ...Args The argument types of the function.
    /// @param ...args The arguments to pass to the function.
    /// @return The result of calling the original function.
    /// @note This function will use the __fastcall calling convention.
    /// @note This function is unsafe because it doesn't lock the mutex. Only use this if you don't care about unhook
    // safety or are worried about the performance cost of locking the mutex.
    template <typename RetT = void, typename... Args> RetT unsafe_fastcall(Args... args) {
        return original<RetT(__fastcall*)(Args...)>()(args...);
    }

private:
    uint8_t* m_target{};
    uint8_t* m_destination{};
    Allocation m_trampoline{};
    std::vector<uint8_t> m_original_bytes{};
    uintptr_t m_trampoline_size{};
    std::recursive_mutex m_mutex{};

    std::expected<void, Error> setup(
        const std::shared_ptr<Allocator>& allocator, uint8_t* target, uint8_t* destination);
    std::expected<void, Error> e9_hook(const std::shared_ptr<Allocator>& allocator);

#ifdef _M_X64
    std::expected<void, Error> ff_hook(const std::shared_ptr<Allocator>& allocator);
#endif

    void destroy();
};
} // namespace safetyhook