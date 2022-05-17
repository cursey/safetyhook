#include <Windows.h>

#include <TlHelp32.h>

#include "safetyhook/ThreadFreezer.hpp"

namespace safetyhook {
ThreadFreezer::ThreadFreezer() {
    auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (snapshot == INVALID_HANDLE_VALUE) {
        return;
    }

    auto pid = GetCurrentProcessId();
    auto tid = GetCurrentThreadId();
    THREADENTRY32 te{};

    te.dwSize = sizeof(te);

    if (Thread32First(snapshot, &te) != FALSE) {
        do {
            if (te.th32OwnerProcessID != pid || te.th32ThreadID == tid) {
                continue;
            }

            FrozenThread thread{};

            thread.thread_id = te.th32ThreadID;
            thread.handle =
                OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);

            if (thread.handle == NULL) {
                continue;
            }

            thread.ctx.ContextFlags = CONTEXT_FULL;

            if (SuspendThread(thread.handle) == (DWORD)-1 || GetThreadContext(thread.handle, &thread.ctx) == FALSE) {
                CloseHandle(thread.handle);
                continue;
            }

            m_frozen_threads.emplace_back(thread);
        } while (Thread32Next(snapshot, &te));
    }

    CloseHandle(snapshot);
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
}