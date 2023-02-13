#pragma once

#include <cstdint>
#include <memory>

#include "safetyhook/Context.hpp"

namespace safetyhook {
class Factory;
class InlineHook;

class MidHook final {
public:
    MidHook() = delete;
    MidHook(const MidHook&) = delete;
    MidHook(MidHook&&) noexcept = delete;
    MidHook& operator=(const MidHook&) = delete;
    MidHook& operator=(MidHook&&) noexcept = delete;

    ~MidHook();

    [[nodiscard]] auto target() const { return m_target; }
    [[nodiscard]] auto destination() const { return m_destination; }

private:
    friend Builder;

    std::shared_ptr<Factory> m_factory{};
    std::unique_ptr<InlineHook> m_hook{};
    uintptr_t m_target{};
    uintptr_t m_stub{};
    MidHookFn m_destination{};

    MidHook(std::shared_ptr<Factory> factory, uintptr_t target, MidHookFn destination);
};
} // namespace safetyhook