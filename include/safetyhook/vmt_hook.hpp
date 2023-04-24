/// @file safetyhook/vmt_hook.hpp
/// @brief VMT hooking classes

#pragma once

#include <cstdint>
#include <expected>
#include <vector>

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

    void destroy();
};

class VmtHook final {
public:
    class Error {};
    [[nodiscard]] static std::expected<VmtHook, Error> create(void* object);

    VmtHook() = default;
    VmtHook(const VmtHook&) = delete;
    VmtHook(VmtHook&& other) noexcept;
    VmtHook& operator=(const VmtHook&) = delete;
    VmtHook& operator=(VmtHook&& other) noexcept;
    ~VmtHook();

    void reset();

    [[nodiscard]] std::expected<VmHook, Error> hook_method(size_t index, FnPtr auto new_function) {
        VmHook hook{};

        hook.m_original_vm = m_new_vmt[index];
        hook.m_new_vm = reinterpret_cast<uint8_t*>(new_function);
        hook.m_vmt_entry = &m_new_vmt[index];
        m_new_vmt[index] = hook.m_new_vm;

        return hook;
    }

private:
    void* m_object{};
    uint8_t** m_original_vmt{};
    std::vector<uint8_t*> m_new_vmt{};

    void destroy();
};
} // namespace safetyhook
