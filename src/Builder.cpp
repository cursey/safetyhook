#include "safetyhook/Factory.hpp"
#include "safetyhook/InlineHook.hpp"
#include "safetyhook/MidHook.hpp"

#include "safetyhook/Builder.hpp"

namespace safetyhook {
InlineHook Builder::create_inline(void* target, void* destination) {
    return InlineHook{m_factory, (uintptr_t)target, (uintptr_t)destination};
}

MidHook Builder::create_mid(void* target, MidHookFn destination) {
    return MidHook{m_factory, (uintptr_t)target, destination};
}

Builder::Builder(std::shared_ptr<Factory> factory) : m_factory{std::move(factory)} {
}

uintptr_t Builder::allocate(size_t size) {
    std::scoped_lock lock{m_factory->m_mutex};
    return m_factory->allocate(size);
}

uintptr_t Builder::allocate_near(const std::vector<uintptr_t>& desired_addresses, size_t size, size_t max_distance) {
    std::scoped_lock lock{m_factory->m_mutex};
    return m_factory->allocate_near(desired_addresses, size, max_distance);
}

void Builder::free(uintptr_t address, size_t size) {
    std::scoped_lock lock{m_factory->m_mutex};
    m_factory->free(address, size);
}
} // namespace safetyhook