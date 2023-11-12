/// @file safetyhook/thread_freezer.hpp
/// @brief A class for freezing all threads in the process.

#pragma once

#include <cstdint>
#include <functional>

namespace safetyhook {
using FixIpFn = std::function<void(uint8_t* old_ip, uint8_t* new_ip)>;

/// @brief Executes a function while all other threads are frozen. Also allows for visiting each frozen thread and
/// modifying it's context.
/// @param run_fn The function to run while all other threads are frozen.
/// @param visit_fn The function that will be called for each frozen thread.
/// @note The visit function will be called in the order that the threads were frozen.
/// @note The visit function will be called before the run function.
/// @note Keep the logic inside run_fn and visit_fn as simple as possible to avoid deadlocks.
void execute_while_frozen(
    const std::function<void()>& run_fn, const std::function<void(uint32_t, const FixIpFn&)>& visit_fn = {});
} // namespace safetyhook