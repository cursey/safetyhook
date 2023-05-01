/// @file safetyhook/vmt_hook.hpp
/// @brief VMT hooking classes

#pragma once

#include <cstdint>
#include <expected>
#include <unordered_map>

#include <safetyhook/allocator.hpp>
#include <safetyhook/utility.hpp>

namespace safetyhook {
class VmHook final {
public:
    VmHook() = default;
    VmHook(const VmHook&) = delete;
    VmHook(VmHook&& other) noexcept;
    VmHook& operator=(const VmHook&) = delete;
    VmHook& operator=(VmHook&& other) noexcept;
    ~VmHook();

    void reset();

    template <typename T> [[nodiscard]] T original() const { return reinterpret_cast<T>(m_original_vm); }

    template <typename RetT = void, typename... Args> RetT call(Args... args) {
        return original<RetT (*)(Args...)>()(args...);
    }

    template <typename RetT = void, typename... Args> RetT ccall(Args... args) {
        return original<RetT(__cdecl*)(Args...)>()(args...);
    }

    template <typename RetT = void, typename... Args> RetT thiscall(Args... args) {
        return original<RetT(__thiscall*)(Args...)>()(args...);
    }

    template <typename RetT = void, typename... Args> RetT stdcall(Args... args) {
        return original<RetT(__stdcall*)(Args...)>()(args...);
    }

    template <typename RetT = void, typename... Args> RetT fastcall(Args... args) {
        return original<RetT(__fastcall*)(Args...)>()(args...);
    }

private:
    friend class VmtHook;

    uint8_t* m_original_vm{};
    uint8_t* m_new_vm{};
    uint8_t** m_vmt_entry{};

    // This keeps the allocation alive until the hook is destroyed.
    std::shared_ptr<Allocation> m_new_vmt_allocation{};

    void destroy();
};

class VmtHook final {
public:
    struct Error {
        enum : uint8_t { BAD_ALLOCATION } type;

        union {
            Allocator::Error allocator_error;
        };

        [[nodiscard]] static Error bad_allocation(Allocator::Error err) {
            return {.type = BAD_ALLOCATION, .allocator_error = err};
        }
    };

    [[nodiscard]] static std::expected<VmtHook, Error> create(void* object);

    VmtHook() = default;
    VmtHook(const VmtHook&) = delete;
    VmtHook(VmtHook&& other) noexcept;
    VmtHook& operator=(const VmtHook&) = delete;
    VmtHook& operator=(VmtHook&& other) noexcept;
    ~VmtHook();

    void apply(void* object);
    void remove(void* object);

    void reset();

    [[nodiscard]] std::expected<VmHook, Error> hook_method(size_t index, FnPtr auto new_function) {
        VmHook hook{};

        ++index; // Skip RTTI pointer.
        hook.m_original_vm = m_new_vmt[index];
        store(reinterpret_cast<uint8_t*>(&hook.m_new_vm), new_function);
        hook.m_vmt_entry = &m_new_vmt[index];
        hook.m_new_vmt_allocation = m_new_vmt_allocation;
        m_new_vmt[index] = hook.m_new_vm;

        return hook;
    }

private:
    // Map of object instance to their original VMT.
    std::unordered_map<void*, uint8_t**> m_objects{};

    // The allocation is a shared_ptr, so it can be shared with VmHooks to ensure the memory is kept alive.
    std::shared_ptr<Allocation> m_new_vmt_allocation{};
    uint8_t** m_new_vmt{};

    void destroy();
};
} // namespace safetyhook
