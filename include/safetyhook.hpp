#pragma once

#include "safetyhook/inline_hook.hpp"
#include "safetyhook/mid_hook.hpp"
#include "safetyhook/thread_freezer.hpp"
#include "safetyhook/easy.hpp"

using SafetyHookContext = safetyhook::Context;
using SafetyHookInline = safetyhook::InlineHook;
using SafetyHookMid = safetyhook::MidHook;
using SafetyInlineHook [[deprecated("Use SafetyHookInline instead.")]] = safetyhook::InlineHook;
using SafetyMidHook [[deprecated("Use SafetyHookMid instead.")]] = safetyhook::MidHook;
using SafetyThreadFreezer = safetyhook::ThreadFreezer;
