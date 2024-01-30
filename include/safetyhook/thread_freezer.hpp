/// @file safetyhook/thread_freezer.hpp
/// @brief A class for freezing all threads in the process.

#pragma once

#include <cstdint>
#include <functional>

namespace safetyhook {
using ThreadId = uint32_t;
using ThreadHandle = void*;
using ThreadContext = void*;

/// @brief Executes a function while all other threads are frozen. Also allows for visiting each frozen thread and
/// modifying it's context.
/// @param run_fn The function to run while all other threads are frozen.
/// @param visit_fn The function that will be called for each frozen thread.
/// @note The visit function will be called in the order that the threads were frozen.
/// @note The visit function will be called before the run function.
/// @note Keep the logic inside run_fn and visit_fn as simple as possible to avoid deadlocks.
void execute_while_frozen(const std::function<void()>& run_fn,
    const std::function<void(ThreadId, ThreadHandle, ThreadContext)>& visit_fn = {});

/// @brief Will modify the context of a thread's IP to point to a new address if its IP is at the old address.
/// @param ctx The thread context to modify.
/// @param old_ip The old IP address.
/// @param new_ip The new IP address.
void fix_ip(ThreadContext ctx, uint8_t* old_ip, uint8_t* new_ip);
} // namespace safetyhook