#pragma once

#include <memory>

#include "safetyhook/Factory.hpp"
#include "safetyhook/InlineHook.hpp"
#include "safetyhook/MidHook.hpp"

using SafetyHookFactory = safetyhook::Factory;
using SafetyInlineHook = std::unique_ptr<safetyhook::InlineHook>;
using SafetyMidHook = std::unique_ptr<safetyhook::MidHook>;
using SafetyHookContext = safetyhook::Context;
