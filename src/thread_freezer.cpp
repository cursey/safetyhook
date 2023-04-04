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
void execute_while_frozen(std::function<void()> run_fn, std::function<void(uint32_t, HANDLE, CONTEXT&)> visit_fn) {
    // Freeze all threads.
    int num_threads_frozen{};
    auto first_run = true;

    do {
        HANDLE thread{};
        num_threads_frozen = 0;

        while (true) {
            HANDLE next_thread{};
            const auto status = NtGetNextThread(GetCurrentProcess(), thread,
                THREAD_QUERY_LIMITED_INFORMATION | THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, 0,
                0, &next_thread);

            if (thread != nullptr) {
                CloseHandle(thread);
            }

            if (!NT_SUCCESS(status)) {
                break;
            }

            thread = next_thread;

            const auto thread_id = GetThreadId(thread);

            if (thread_id == 0 || thread_id == GetCurrentThreadId()) {
                continue;
            }

            const auto suspend_count = SuspendThread(thread);

            if (suspend_count == static_cast<DWORD>(-1)) {
                continue;
            }

            // Check if the thread was already frozen. Only resume if the thread was already frozen and it wasn't the
            // first run of this freeze loop to account for threads that may have already been frozen for other reasons.
            if (suspend_count != 0 && !first_run) {
                ResumeThread(thread);
                continue;
            }

            auto thread_ctx = CONTEXT{};

            thread_ctx.ContextFlags = CONTEXT_FULL;

            if (GetThreadContext(thread, &thread_ctx) == FALSE) {
                continue;
            }

            if (visit_fn) {
                visit_fn(thread_id, thread, thread_ctx);
            }

            ++num_threads_frozen;
        }

        first_run = false;
    } while (num_threads_frozen != 0);

    // Run the function.
    if (run_fn) {
        run_fn();
    }

    // Resume all threads.
    HANDLE thread{};

    while (true) {
        HANDLE next_thread{};
        const auto status = NtGetNextThread(GetCurrentProcess(), thread,
            THREAD_QUERY_LIMITED_INFORMATION | THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, 0, 0,
            &next_thread);

        if (thread != nullptr) {
            CloseHandle(thread);
        }

        if (!NT_SUCCESS(status)) {
            break;
        }

        thread = next_thread;

        const auto thread_id = GetThreadId(thread);

        if (thread_id == 0 || thread_id == GetCurrentThreadId()) {
            continue;
        }

        ResumeThread(thread);
    }
}

void fix_ip(CONTEXT& ctx, uintptr_t old_ip, uintptr_t new_ip) {
#ifdef _M_X64
    auto ip = ctx.Rip;
#else
    auto ip = ctx.Eip;
#endif

    if (ip == old_ip) {
        ip = new_ip;
    }

#ifdef _M_X64
    ctx.Rip = ip;
#else
    ctx.Eip = ip;
#endif
}
} // namespace safetyhook