#pragma once

#include <cstdint>
#include <memory>

#include "safetyhook/allocator.hpp"
#include "safetyhook/context.hpp"
#include "safetyhook/inline_hook.hpp"

namespace safetyhook {
class MidHook final {
public:
    struct Error {
        enum Type {
            BAD_ALLOCATION,
            BAD_INLINE_HOOK,
        };

        Type type;

        union Extra {
            Allocator::Error allocator_error;
            InlineHook::Error inline_hook_error;
        };

        Extra extra;

        Error() = default;
        Error(Type type) : type{type} {}
        Error(Allocator::Error allocator_error) : type{Type::BAD_ALLOCATION} {
            extra.allocator_error = allocator_error;
        }
        Error(InlineHook::Error inline_hook_error) : type{Type::BAD_INLINE_HOOK} {
            extra.inline_hook_error = inline_hook_error;
        }
    };

    [[nodiscard]] static std::expected<MidHook, Error> create(void* target, MidHookFn destination);
    [[nodiscard]] static std::expected<MidHook, Error> create(uintptr_t target, MidHookFn destination);
    [[nodiscard]] static std::expected<MidHook, Error> create(
        std::shared_ptr<Allocator> allocator, void* target, MidHookFn destination);
    [[nodiscard]] static std::expected<MidHook, Error> create(
        std::shared_ptr<Allocator> allocator, uintptr_t target, MidHookFn destination);

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
    std::shared_ptr<Allocator> m_allocator{};
    InlineHook m_hook{};
    uintptr_t m_target{};
    uintptr_t m_stub{};
    MidHookFn m_destination{};

    std::expected<void, Error> setup();
};
} // namespace safetyhook