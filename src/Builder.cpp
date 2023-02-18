#include "safetyhook/Factory.hpp"
#include "safetyhook/InlineHook.hpp"
#include "safetyhook/MidHook.hpp"
#include "safetyhook/ThreadFreezer.hpp"

#include "safetyhook/Builder.hpp"

namespace safetyhook {
Builder::~Builder() {
    if (m_factory->m_builder == this) {
        transact();
        m_factory->m_builder = nullptr;
    }
}

InlineHook Builder::create_inline(void* target, void* destination) {
    InlineHook hook{};
    InlineHookInfo hook_info{&hook, (uintptr_t)target, (uintptr_t)destination};

    m_inline_hooks->emplace_back(hook_info);

    return hook;
}

MidHook Builder::create_mid(void* target, MidHookFn destination) {
    MidHook hook{};
    MidHookInfo hook_info{&hook, (uintptr_t)target, destination};

    m_mid_hooks->emplace_back(hook_info);

    return hook;
}

bool Builder::transact() {
    // Call fix_ip(0, 0) to cause a ThreadFreezer to be constructed for the active Factory Builder.
    fix_ip(0, 0);

    auto is_successful = true;

    for (auto& hook_info : *m_inline_hooks) {
        *hook_info.hook = InlineHook{m_factory, hook_info.target, hook_info.destination};

        if (!(*hook_info.hook)) {
            is_successful = false;
        }
    }

    for (auto& hook_info : *m_mid_hooks) {
        *hook_info.hook = MidHook{m_factory, hook_info.target, hook_info.destination};

        if (!(*hook_info.hook)) {
            is_successful = false;
        }
    }

    if (!is_successful) {
        for (auto& hook_info : *m_inline_hooks) {
            *hook_info.hook = InlineHook{};
        }

        for (auto& hook_info : *m_mid_hooks) {
            *hook_info.hook = MidHook{};
        }
    }

    m_inline_hooks->clear();
    m_mid_hooks->clear();

    return is_successful;
}

Builder::Builder(std::shared_ptr<Factory> factory) : m_factory{std::move(factory)}, m_factory_lock{m_factory->m_mutex} {
    if (m_factory->m_builder == nullptr) {
        m_factory->m_builder = this;
        m_inline_hooks = std::make_shared<std::vector<InlineHookInfo>>();
        m_mid_hooks = std::make_shared<std::vector<MidHookInfo>>();
    } else {
        m_inline_hooks = m_factory->m_builder->m_inline_hooks;
        m_mid_hooks = m_factory->m_builder->m_mid_hooks;
    }
}

void Builder::fix_ip(uintptr_t old_ip, uintptr_t new_ip) {
    auto active_builder = m_factory->m_builder;

    if (active_builder->m_threads == nullptr) {
        active_builder->m_threads = std::make_unique<ThreadFreezer>();
    }

    active_builder->m_threads->fix_ip(old_ip, new_ip);
}

uintptr_t Builder::allocate(size_t size) {
    return m_factory->allocate(size);
}

uintptr_t Builder::allocate_near(const std::vector<uintptr_t>& desired_addresses, size_t size, size_t max_distance) {
    return m_factory->allocate_near(desired_addresses, size, max_distance);
}

void Builder::free(uintptr_t address, size_t size) {
    m_factory->free(address, size);
}

void Builder::notify_hook_moved(InlineHook* from, InlineHook* to) {
    if (to != nullptr) {
        for (auto& hook_info : *m_inline_hooks) {
            if (hook_info.hook == from) {
                hook_info.hook = to;
                break;
            }
        }
    } else {
        m_inline_hooks->erase(std::remove_if(m_inline_hooks->begin(), m_inline_hooks->end(),
                                  [from](const InlineHookInfo& hook_info) { return hook_info.hook == from; }),
            m_inline_hooks->end());
    }
}

void Builder::notify_hook_moved(MidHook* from, MidHook* to) {
    if (to != nullptr) {
        for (auto& hook_info : *m_mid_hooks) {
            if (hook_info.hook == from) {
                hook_info.hook = to;
                break;
            }
        }
    } else {
        m_mid_hooks->erase(std::remove_if(m_mid_hooks->begin(), m_mid_hooks->end(),
                               [from](const MidHookInfo& hook_info) { return hook_info.hook == from; }),
            m_mid_hooks->end());
    }
}
} // namespace safetyhook
