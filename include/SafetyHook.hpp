#pragma once

#include <memory>

#include "safetyhook/Builder.hpp"
#include "safetyhook/Factory.hpp"
#include "safetyhook/InlineHook.hpp"
#include "safetyhook/MidHook.hpp"

using SafetyHookBuilder = safetyhook::Builder;
using SafetyHookFactory = safetyhook::Factory;
using SafetyHookContext = safetyhook::Context;
using SafetyHookInline = safetyhook::InlineHook;
using SafetyHookMid = safetyhook::MidHook;
using SafetyInlineHook [[deprecated("Use SafetyHookInline instead.")]] = safetyhook::InlineHook;
using SafetyMidHook [[deprecated("Use SafetyHookMid instead.")]] = safetyhook::MidHook;
