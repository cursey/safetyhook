#include <map>
#include <mutex>

#if __has_include(<Windows.h>)
#include <Windows.h>
#elif __has_include(<windows.h>)
#include <windows.h>
#else
#error "Windows.h not found"
#endif

#include "safetyhook/common.hpp"
#include "safetyhook/utility.hpp"

#include "safetyhook/thread_freezer.hpp"

namespace safetyhook {
struct TrapInfo {
    uint8_t* page_start;
    uint8_t* page_end;
    uint8_t* from;
    uint8_t* to;
    size_t len;
};

class TrapManager {
public:
    static std::mutex mutex;
    static std::unique_ptr<TrapManager> instance;

    TrapManager() { m_trap_veh = AddVectoredExceptionHandler(1, trap_handler); }
    ~TrapManager() {
        if (m_trap_veh != nullptr) {
            RemoveVectoredExceptionHandler(m_trap_veh);
        }
    }

    TrapInfo* find_trap(uint8_t* address) {
        auto search = std::find_if(m_traps.begin(), m_traps.end(), [address](auto& trap) {
            return address >= trap.second.from && address < trap.second.from + trap.second.len;
        });

        if (search == m_traps.end()) {
            return nullptr;
        }

        return &search->second;
    }

    TrapInfo* find_trap_page(uint8_t* address) {
        auto search = std::find_if(m_traps.begin(), m_traps.end(),
            [address](auto& trap) { return address >= trap.second.page_start && address < trap.second.page_end; });

        if (search == m_traps.end()) {
            return nullptr;
        }

        return &search->second;
    }

    void add_trap(uint8_t* from, uint8_t* to, size_t len) {
        m_traps.insert_or_assign(from, TrapInfo{.page_start = align_down(from, 0x1000),
                                           .page_end = align_up(from + len, 0x1000),
                                           .from = from,
                                           .to = to,
                                           .len = len});
    }

private:
    std::map<uint8_t*, TrapInfo> m_traps;
    PVOID m_trap_veh{};

    static LONG CALLBACK trap_handler(PEXCEPTION_POINTERS exp) {
        auto exception_code = exp->ExceptionRecord->ExceptionCode;

        if (exception_code != EXCEPTION_ACCESS_VIOLATION) {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        std::scoped_lock lock{mutex};
        auto* faulting_address = reinterpret_cast<uint8_t*>(exp->ExceptionRecord->ExceptionInformation[1]);
        auto* trap = instance->find_trap(faulting_address);

        if (trap == nullptr) {
            if (instance->find_trap_page(faulting_address) != nullptr) {
                return EXCEPTION_CONTINUE_EXECUTION;
            } else {
                return EXCEPTION_CONTINUE_SEARCH;
            }
        }

        auto* ctx = exp->ContextRecord;

        for (size_t i = 0; i < trap->len; i++) {
            fix_ip(ctx, trap->from + i, trap->to + i);
        }

        return EXCEPTION_CONTINUE_EXECUTION;
    }
};

std::mutex TrapManager::mutex;
std::unique_ptr<TrapManager> TrapManager::instance;

void find_me() {
}

void trap_threads(uint8_t* from, uint8_t* to, size_t len, const std::function<void()>& run_fn) {
    MEMORY_BASIC_INFORMATION find_me_mbi{};
    MEMORY_BASIC_INFORMATION from_mbi{};
    MEMORY_BASIC_INFORMATION to_mbi{};

    VirtualQuery(reinterpret_cast<void*>(find_me), &find_me_mbi, sizeof(find_me_mbi));
    VirtualQuery(from, &from_mbi, sizeof(from_mbi));
    VirtualQuery(to, &to_mbi, sizeof(to_mbi));

    auto new_protect = PAGE_READWRITE;

    if (from_mbi.AllocationBase == find_me_mbi.AllocationBase || to_mbi.AllocationBase == find_me_mbi.AllocationBase) {
        new_protect = PAGE_EXECUTE_READWRITE;
    }

    std::scoped_lock lock{TrapManager::mutex};

    if (TrapManager::instance == nullptr) {
        TrapManager::instance = std::make_unique<TrapManager>();
    }

    TrapManager::instance->add_trap(from, to, len);

    DWORD from_protect;
    DWORD to_protect;

    VirtualProtect(from, len, new_protect, &from_protect);
    VirtualProtect(to, len, new_protect, &to_protect);

    if (run_fn) {
        run_fn();
    }

    VirtualProtect(to, len, to_protect, &to_protect);
    VirtualProtect(from, len, from_protect, &from_protect);
}

void fix_ip(ThreadContext thread_ctx, uint8_t* old_ip, uint8_t* new_ip) {
    auto* ctx = reinterpret_cast<CONTEXT*>(thread_ctx);

#if SAFETYHOOK_ARCH_X86_64
    auto ip = ctx->Rip;
#elif SAFETYHOOK_ARCH_X86_32
    auto ip = ctx->Eip;
#endif

    if (ip == reinterpret_cast<uintptr_t>(old_ip)) {
        ip = reinterpret_cast<uintptr_t>(new_ip);
    }

#if SAFETYHOOK_ARCH_X86_64
    ctx->Rip = ip;
#elif SAFETYHOOK_ARCH_X86_32
    ctx->Eip = ip;
#endif
}
} // namespace safetyhook