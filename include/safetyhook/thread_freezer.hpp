/// @file safetyhook/thread_freezer.hpp
/// @brief A class for freezing all threads in the process.

#pragma once

#include <cstdint>
#include <functional>

namespace safetyhook {
using ThreadId = uint32_t;
using ThreadHandle = void*;
using ThreadContext = void*;

void trap_threads(uint8_t* from, uint8_t* to, size_t len, const std::function<void()>& run_fn);

/// @brief Will modify the context of a thread's IP to point to a new address if its IP is at the old address.
/// @param ctx The thread context to modify.
/// @param old_ip The old IP address.
/// @param new_ip The new IP address.
void fix_ip(ThreadContext ctx, uint8_t* old_ip, uint8_t* new_ip);
} // namespace safetyhook