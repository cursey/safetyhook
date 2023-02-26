#include <Windows.h>
#include <winternl.h>

#include "safetyhook/ThreadFreezer.hpp"

extern "C" {
NTSTATUS
NTAPI
NtGetNextThread(HANDLE ProcessHandle, HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes,
    ULONG Flags, PHANDLE NewThreadHandle);
}

namespace safetyhook {
ThreadFreezer::ThreadFreezer() {
    auto peb = reinterpret_cast<uintptr_t>(NtCurrentTeb()->ProcessEnvironmentBlock);

#if defined(_M_X64)
    auto loader_lock = *reinterpret_cast<RTL_CRITICAL_SECTION**>(peb + 0x110);
#elif defined(_M_IX86)
    auto loader_lock = *reinterpret_cast<RTL_CRITICAL_SECTION**>(peb + 0xA0);
#else
#error "Unsupported architecture"
#endif
    EnterCriticalSection(loader_lock);

    HANDLE thread_handle{};

    while (true) {
        auto status = NtGetNextThread(GetCurrentProcess(), thread_handle,
            THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, 0, 0, &thread_handle);

        if (status != 0) {
            break;
        }

        auto thread_id = GetThreadId(thread_handle);

        if (thread_id == 0 || thread_id == GetCurrentThreadId()) {
            continue;
        }

        auto thread_ctx = CONTEXT{};

        thread_ctx.ContextFlags = CONTEXT_FULL;

        if (!GetThreadContext(thread_handle, &thread_ctx)) {
            continue;
        }

        SuspendThread(thread_handle);
        m_frozen_threads.push_back({thread_id, thread_handle, thread_ctx});
    }

    LeaveCriticalSection(loader_lock);
}

ThreadFreezer::~ThreadFreezer() {
    for (auto& thread : m_frozen_threads) {
        SetThreadContext(thread.handle, &thread.ctx);
        ResumeThread(thread.handle);
        CloseHandle(thread.handle);
    }
}

void ThreadFreezer::fix_ip(uintptr_t old_ip, uintptr_t new_ip) {
    for (auto& thread : m_frozen_threads) {
#ifdef _M_X64
        auto ip = thread.ctx.Rip;
#else
        auto ip = thread.ctx.Eip;
#endif

        if (ip == old_ip) {
            ip = new_ip;
        }

#ifdef _M_X64
        thread.ctx.Rip = ip;
#else
        thread.ctx.Eip = ip;
#endif
    }
}
} // namespace safetyhook