#pragma once

#include <cstdint>
#include <memory>

#include "safetyhook/Context.hpp"
#include "safetyhook/InlineHook.hpp"

namespace safetyhook {
class Factory;
class Builder;

class MidHook final {
public:
    MidHook() = default;
    MidHook(const MidHook&) = delete;
    MidHook(MidHook&& other) noexcept;
    MidHook& operator=(const MidHook&) = delete;
    MidHook& operator=(MidHook&& other) noexcept;

    ~MidHook();

    void reset();

    [[nodiscard]] auto target() const { return m_target; }
    [[nodiscard]] auto destination() const { return m_destination; }
    operator bool() const { return m_stub != 0; }

private:
    friend Builder;

    std::shared_ptr<Factory> m_factory{};
    InlineHook m_hook{};
    uintptr_t m_target{};
    uintptr_t m_stub{};
    MidHookFn m_destination{};

    MidHook(std::shared_ptr<Factory> factory, uintptr_t target, MidHookFn destination);
};
} // namespace safetyhook