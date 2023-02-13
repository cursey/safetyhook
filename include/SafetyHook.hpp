#pragma once

#include <memory>

#include "safetyhook/Builder.hpp"
#include "safetyhook/Factory.hpp"
#include "safetyhook/InlineHook.hpp"
#include "safetyhook/MidHook.hpp"

using SafetyHookBuilder = safetyhook::Builder;
using SafetyHookFactory = safetyhook::Factory;
using SafetyHookContext = safetyhook::Context;
using SafetyHookInline = std::unique_ptr<safetyhook::InlineHook>;
using SafetyHookMid = std::unique_ptr<safetyhook::MidHook>;
using SafetyInlineHook [[deprecated("Use SafetyHookInline instead.")]] = std::unique_ptr<safetyhook::InlineHook>;
using SafetyMidHook [[deprecated("Use SafetyHookMid instead.")]] = std::unique_ptr<safetyhook::MidHook>;
