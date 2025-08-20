// This is the OS abstraction layer.
#pragma once

#ifndef SAFETYHOOK_USE_CXXMODULES
#include <cstdint>
#include <expected>
#include <functional>
#else
import std.compat;
#endif

#include "safetyhook/common.hpp"

namespace safetyhook {

enum class OsError {
    FAILED_TO_ALLOCATE,
    FAILED_TO_PROTECT,
    FAILED_TO_QUERY,
    FAILED_TO_GET_NEXT_THREAD,
    FAILED_TO_GET_THREAD_CONTEXT,
    FAILED_TO_SET_THREAD_CONTEXT,
    FAILED_TO_FREEZE_THREAD,
    FAILED_TO_UNFREEZE_THREAD,
    FAILED_TO_GET_THREAD_ID,
};

struct VmAccess {
    bool read : 1;
    bool write : 1;
    bool execute : 1;

    constexpr bool operator==(const VmAccess& other) const {
        return read == other.read && write == other.write && execute == other.execute;
    }
};

inline constexpr VmAccess VM_ACCESS_R{true, false, false};
inline constexpr VmAccess VM_ACCESS_RW{true, true, false};
inline constexpr VmAccess VM_ACCESS_RX{true, false, true};
inline constexpr VmAccess VM_ACCESS_RWX{true, true, true};

struct VmBasicInfo {
    uint8_t* address;
    size_t size;
    VmAccess access;
    bool is_free;
};

std::expected<uint8_t*, OsError> SAFETYHOOK_API vm_allocate(uint8_t* address, size_t size, VmAccess access);
void SAFETYHOOK_API vm_free(uint8_t* address);
std::expected<uint32_t, OsError> SAFETYHOOK_API vm_protect(uint8_t* address, size_t size, VmAccess access);
std::expected<uint32_t, OsError> SAFETYHOOK_API vm_protect(uint8_t* address, size_t size, uint32_t access);
std::expected<VmBasicInfo, OsError> SAFETYHOOK_API vm_query(uint8_t* address);
bool SAFETYHOOK_API vm_is_readable(uint8_t* address, size_t size);
bool SAFETYHOOK_API vm_is_writable(uint8_t* address, size_t size);
bool SAFETYHOOK_API vm_is_executable(uint8_t* address);

struct SystemInfo {
    uint32_t page_size;
    uint32_t allocation_granularity;
    uint8_t* min_address;
    uint8_t* max_address;
};

SystemInfo SAFETYHOOK_API system_info();

using ThreadContext = void*;

void SAFETYHOOK_API trap_threads(uint8_t* from, uint8_t* to, size_t len, const std::function<void()>& run_fn);

/// @brief Will modify the context of a thread's IP to point to a new address if its IP is at the old address.
/// @param ctx The thread context to modify.
/// @param old_ip The old IP address.
/// @param new_ip The new IP address.
void SAFETYHOOK_API fix_ip(ThreadContext ctx, uint8_t* old_ip, uint8_t* new_ip);

} // namespace safetyhook
