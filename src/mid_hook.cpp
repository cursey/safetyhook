#include <algorithm>
#include <array>

#include <safetyhook/allocator.hpp>
#include <safetyhook/inline_hook.hpp>
#include <safetyhook/utility.hpp>

#include <safetyhook/mid_hook.hpp>

namespace safetyhook {

#ifdef _M_X64
constexpr std::array<uint8_t, 391> asm_data = {0xFF, 0x35, 0x79, 0x01, 0x00, 0x00, 0x54, 0x54, 0x55, 0x50, 0x53, 0x51,
    0x52, 0x56, 0x57, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,
    0x9C, 0x48, 0x81, 0xEC, 0x00, 0x01, 0x00, 0x00, 0xF3, 0x44, 0x0F, 0x7F, 0xBC, 0x24, 0xF0, 0x00, 0x00, 0x00, 0xF3,
    0x44, 0x0F, 0x7F, 0xB4, 0x24, 0xE0, 0x00, 0x00, 0x00, 0xF3, 0x44, 0x0F, 0x7F, 0xAC, 0x24, 0xD0, 0x00, 0x00, 0x00,
    0xF3, 0x44, 0x0F, 0x7F, 0xA4, 0x24, 0xC0, 0x00, 0x00, 0x00, 0xF3, 0x44, 0x0F, 0x7F, 0x9C, 0x24, 0xB0, 0x00, 0x00,
    0x00, 0xF3, 0x44, 0x0F, 0x7F, 0x94, 0x24, 0xA0, 0x00, 0x00, 0x00, 0xF3, 0x44, 0x0F, 0x7F, 0x8C, 0x24, 0x90, 0x00,
    0x00, 0x00, 0xF3, 0x44, 0x0F, 0x7F, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00, 0xF3, 0x0F, 0x7F, 0x7C, 0x24, 0x70, 0xF3,
    0x0F, 0x7F, 0x74, 0x24, 0x60, 0xF3, 0x0F, 0x7F, 0x6C, 0x24, 0x50, 0xF3, 0x0F, 0x7F, 0x64, 0x24, 0x40, 0xF3, 0x0F,
    0x7F, 0x5C, 0x24, 0x30, 0xF3, 0x0F, 0x7F, 0x54, 0x24, 0x20, 0xF3, 0x0F, 0x7F, 0x4C, 0x24, 0x10, 0xF3, 0x0F, 0x7F,
    0x04, 0x24, 0x48, 0x8B, 0x8C, 0x24, 0x80, 0x01, 0x00, 0x00, 0x48, 0x83, 0xC1, 0x10, 0x48, 0x89, 0x8C, 0x24, 0x80,
    0x01, 0x00, 0x00, 0x48, 0x8D, 0x0C, 0x24, 0x48, 0x89, 0xE3, 0x48, 0x83, 0xEC, 0x30, 0x48, 0x83, 0xE4, 0xF0, 0xFF,
    0x15, 0xA8, 0x00, 0x00, 0x00, 0x48, 0x89, 0xDC, 0xF3, 0x0F, 0x6F, 0x04, 0x24, 0xF3, 0x0F, 0x6F, 0x4C, 0x24, 0x10,
    0xF3, 0x0F, 0x6F, 0x54, 0x24, 0x20, 0xF3, 0x0F, 0x6F, 0x5C, 0x24, 0x30, 0xF3, 0x0F, 0x6F, 0x64, 0x24, 0x40, 0xF3,
    0x0F, 0x6F, 0x6C, 0x24, 0x50, 0xF3, 0x0F, 0x6F, 0x74, 0x24, 0x60, 0xF3, 0x0F, 0x6F, 0x7C, 0x24, 0x70, 0xF3, 0x44,
    0x0F, 0x6F, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00, 0xF3, 0x44, 0x0F, 0x6F, 0x8C, 0x24, 0x90, 0x00, 0x00, 0x00, 0xF3,
    0x44, 0x0F, 0x6F, 0x94, 0x24, 0xA0, 0x00, 0x00, 0x00, 0xF3, 0x44, 0x0F, 0x6F, 0x9C, 0x24, 0xB0, 0x00, 0x00, 0x00,
    0xF3, 0x44, 0x0F, 0x6F, 0xA4, 0x24, 0xC0, 0x00, 0x00, 0x00, 0xF3, 0x44, 0x0F, 0x6F, 0xAC, 0x24, 0xD0, 0x00, 0x00,
    0x00, 0xF3, 0x44, 0x0F, 0x6F, 0xB4, 0x24, 0xE0, 0x00, 0x00, 0x00, 0xF3, 0x44, 0x0F, 0x6F, 0xBC, 0x24, 0xF0, 0x00,
    0x00, 0x00, 0x48, 0x81, 0xC4, 0x00, 0x01, 0x00, 0x00, 0x9D, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x41,
    0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5F, 0x5E, 0x5A, 0x59, 0x5B, 0x58, 0x5D, 0x48, 0x8D, 0x64, 0x24, 0x08,
    0x5C, 0xC3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
#else
constexpr std::array<uint8_t, 171> asm_data = {0xFF, 0x35, 0xA7, 0x00, 0x00, 0x00, 0x54, 0x54, 0x55, 0x50, 0x53, 0x51,
    0x52, 0x56, 0x57, 0x9C, 0x81, 0xEC, 0x80, 0x00, 0x00, 0x00, 0xF3, 0x0F, 0x7F, 0x7C, 0x24, 0x70, 0xF3, 0x0F, 0x7F,
    0x74, 0x24, 0x60, 0xF3, 0x0F, 0x7F, 0x6C, 0x24, 0x50, 0xF3, 0x0F, 0x7F, 0x64, 0x24, 0x40, 0xF3, 0x0F, 0x7F, 0x5C,
    0x24, 0x30, 0xF3, 0x0F, 0x7F, 0x54, 0x24, 0x20, 0xF3, 0x0F, 0x7F, 0x4C, 0x24, 0x10, 0xF3, 0x0F, 0x7F, 0x04, 0x24,
    0x8B, 0x8C, 0x24, 0xA0, 0x00, 0x00, 0x00, 0x83, 0xC1, 0x08, 0x89, 0x8C, 0x24, 0xA0, 0x00, 0x00, 0x00, 0x54, 0xFF,
    0x15, 0xA3, 0x00, 0x00, 0x00, 0x83, 0xC4, 0x04, 0xF3, 0x0F, 0x6F, 0x04, 0x24, 0xF3, 0x0F, 0x6F, 0x4C, 0x24, 0x10,
    0xF3, 0x0F, 0x6F, 0x54, 0x24, 0x20, 0xF3, 0x0F, 0x6F, 0x5C, 0x24, 0x30, 0xF3, 0x0F, 0x6F, 0x64, 0x24, 0x40, 0xF3,
    0x0F, 0x6F, 0x6C, 0x24, 0x50, 0xF3, 0x0F, 0x6F, 0x74, 0x24, 0x60, 0xF3, 0x0F, 0x6F, 0x7C, 0x24, 0x70, 0x81, 0xC4,
    0x80, 0x00, 0x00, 0x00, 0x9D, 0x5F, 0x5E, 0x5A, 0x59, 0x5B, 0x58, 0x5D, 0x8D, 0x64, 0x24, 0x04, 0x5C, 0xC3, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
#endif

std::expected<MidHook, MidHook::Error> MidHook::create(void* target, MidHookFn destination) {
    return create(Allocator::global(), target, destination);
}

std::expected<MidHook, MidHook::Error> MidHook::create(
    const std::shared_ptr<Allocator>& allocator, void* target, MidHookFn destination) {
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

    auto stub_allocation = allocator->allocate(asm_data.size());

    if (!stub_allocation) {
        return std::unexpected{Error::bad_allocation(stub_allocation.error())};
    }

    m_stub = std::move(*stub_allocation);

    std::copy(asm_data.begin(), asm_data.end(), m_stub.data());

#ifdef _M_X64
    store(m_stub.data() + sizeof(asm_data) - 16, m_destination);
#else
    store(m_stub.data() + sizeof(asm_data) - 8, m_destination);

    // 32-bit has some relocations we need to fix up as well.
    store(m_stub.data() + 0x02, m_stub.data() + m_stub.size() - 4);
    store(m_stub.data() + 0x59, m_stub.data() + m_stub.size() - 8);
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
