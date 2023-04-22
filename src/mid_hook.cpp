#include <algorithm>

#include <safetyhook/allocator.hpp>
#include <safetyhook/inline_hook.hpp>
#include <safetyhook/utility.hpp>

#include <safetyhook/mid_hook.hpp>

namespace safetyhook {

#ifdef _M_X64
constexpr uint8_t asm_data[] = {0x54, 0x55, 0x50, 0x53, 0x51, 0x52, 0x56, 0x57, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52,
    0x41, 0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x9C, 0x48, 0x8D, 0x0C, 0x24, 0x48, 0x89, 0xE3, 0x48,
    0x83, 0xEC, 0x30, 0x48, 0x83, 0xE4, 0xF0, 0xFF, 0x15, 0x22, 0x00, 0x00, 0x00, 0x48, 0x89, 0xDC, 0x9D, 0x41, 0x5F,
    0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5F, 0x5E, 0x5A, 0x59, 0x5B,
    0x58, 0x5D, 0x5C, 0xFF, 0x25, 0x08, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
#else
constexpr uint8_t asm_data[] = {0x54, 0x55, 0x50, 0x53, 0x51, 0x52, 0x56, 0x57, 0x9C, 0x54, 0xFF, 0x15, 0x00, 0x00,
    0x00, 0x00, 0x83, 0xC4, 0x04, 0x9D, 0x5F, 0x5E, 0x5A, 0x59, 0x5B, 0x58, 0x5D, 0x5C, 0xFF, 0x25, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
#endif

std::expected<MidHook, MidHook::Error> MidHook::create(void* target, MidHookFn destination) {
    return create(Allocator::global(), target, destination);
}

std::expected<MidHook, MidHook::Error> MidHook::create(uintptr_t target, MidHookFn destination) {
    return create(Allocator::global(), target, destination);
}

std::expected<MidHook, MidHook::Error> MidHook::create(
    const std::shared_ptr<Allocator>& allocator, void* target, MidHookFn destination) {
    return create(allocator, reinterpret_cast<uintptr_t>(target), destination);
}

std::expected<MidHook, MidHook::Error> MidHook::create(
    const std::shared_ptr<Allocator>& allocator, uintptr_t target, MidHookFn destination) {
    MidHook hook{};

    if (const auto setup_result = hook.setup(allocator, reinterpret_cast<uint8_t*>(target), destination);
        !setup_result) {
        return std::unexpected{setup_result.error()};
    }

    return hook;
}

MidHook::MidHook(MidHook&& other) noexcept {
    *this = std::move(other);
}

MidHook& MidHook::operator=(MidHook&& other) noexcept {
    if (this != &other) {
        m_hook = std::move(other.m_hook);
        m_target = other.m_target;
        m_stub = std::move(other.m_stub);
        m_destination = other.m_destination;

        other.m_target = 0;
        other.m_destination = nullptr;
    }

    return *this;
}

void MidHook::reset() {
    *this = {};
}

std::expected<void, MidHook::Error> MidHook::setup(
    const std::shared_ptr<Allocator>& allocator, uint8_t* target, MidHookFn destination) {
    m_target = target;
    m_destination = destination;

    auto stub_allocation = allocator->allocate(sizeof(asm_data));

    if (!stub_allocation) {
        return std::unexpected{Error::bad_allocation(stub_allocation.error())};
    }

    m_stub = std::move(*stub_allocation);

    std::copy_n(asm_data, sizeof(asm_data), m_stub.data());

#ifdef _M_X64
    store(m_stub.data() + sizeof(asm_data) - 16, m_destination);
#else
    store(m_stub.data() + sizeof(asm_data) - 8, m_destination);

    // 32-bit has some relocations we need to fix up as well.
    store(m_stub.data() + 0xA + 2, m_stub.data() + sizeof(asm_data) - 8);
    store(m_stub.data() + 0x1C + 2, m_stub.data() + sizeof(asm_data) - 4);
#endif

    auto hook_result = InlineHook::create(allocator, m_target, m_stub.data());

    if (!hook_result) {
        m_stub.free();
        return std::unexpected{Error::bad_inline_hook(hook_result.error())};
    }

    m_hook = std::move(*hook_result);

#ifdef _M_X64
    store(m_stub.data() + sizeof(asm_data) - 8, m_hook.trampoline().data());
#else
    store(m_stub.data() + sizeof(asm_data) - 4, m_hook.trampoline().data());
#endif

    return {};
}
} // namespace safetyhook
