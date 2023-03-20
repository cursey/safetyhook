#include <algorithm>

#include <Windows.h>
#include <winternl.h>

#include <safetyhook/thread_freezer.hpp>

#pragma comment(lib, "ntdll")

extern "C" {
NTSTATUS
NTAPI
NtGetNextThread(HANDLE ProcessHandle, HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes,
    ULONG Flags, PHANDLE NewThreadHandle);
}

namespace safetyhook {
ThreadFreezer::ThreadFreezer() {
    size_t num_threads_frozen{};

    do {
        num_threads_frozen = m_frozen_threads.size();
        HANDLE thread{};

        while (true) {
            const auto status = NtGetNextThread(GetCurrentProcess(), thread,
                THREAD_QUERY_LIMITED_INFORMATION | THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, 0,
                0, &thread);

            if (!NT_SUCCESS(status)) {
                break;
            }

            const auto thread_id = GetThreadId(thread);
            const auto already_frozen = std::any_of(m_frozen_threads.begin(), m_frozen_threads.end(),
                [=](const auto& thread) { return thread.thread_id == thread_id; });

            // Don't freeze ourselves or threads we already froze.
            if (thread_id == 0 || thread_id == GetCurrentThreadId() || already_frozen) {
                CloseHandle(thread);
                continue;
            }

            auto thread_ctx = CONTEXT{};

            thread_ctx.ContextFlags = CONTEXT_FULL;

            if (SuspendThread(thread) == static_cast<DWORD>(-1) || GetThreadContext(thread, &thread_ctx) == FALSE) {
                CloseHandle(thread);
                continue;
            }

            m_frozen_threads.push_back({thread_id, thread, thread_ctx});
        }
    } while (num_threads_frozen != m_frozen_threads.size());
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