#if __has_include(<Windows.h>)
#include <Windows.h>
#elif __has_include(<windows.h>)
#include <windows.h>
#else
#error "Windows.h not found"
#endif
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
void execute_while_frozen(
    const std::function<void()>& run_fn, const std::function<void(uint32_t, HANDLE, CONTEXT&)>& visit_fn) {
    // Freeze all threads.
    int num_threads_frozen;
    auto first_run = true;

    ULONG_PTR loader_magic = 0;

    typedef NTSTATUS (WINAPI* PFN_LdrLockLoaderLock)(ULONG Flags, ULONG *State, ULONG_PTR *Cookie);
    typedef NTSTATUS (WINAPI* PFN_LdrUnlockLoaderLock)(ULONG Flags, ULONG_PTR Cookie);

    const auto ntdll = GetModuleHandleW(L"ntdll.dll");

    auto lock_loader = (PFN_LdrLockLoaderLock)GetProcAddress(ntdll, "LdrLockLoaderLock");
    auto unlock_loader = (PFN_LdrUnlockLoaderLock)GetProcAddress(ntdll, "LdrUnlockLoaderLock");

    if (lock_loader != nullptr && unlock_loader != nullptr) {
        lock_loader(0, NULL, &loader_magic);
    }

    do {
        num_threads_frozen = 0;
        HANDLE thread{};

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

            // Check if the thread was already frozen. Only resume if the thread was already frozen, and it wasn't the
            // first run of this freeze loop to account for threads that may have already been frozen for other reasons.
            if (suspend_count != 0 && !first_run) {
                ResumeThread(thread);
                continue;
            }

            CONTEXT thread_ctx{};

            thread_ctx.ContextFlags = CONTEXT_FULL;

            if (GetThreadContext(thread, &thread_ctx) == FALSE) {
                continue;
            }

            if (visit_fn) {
                // Unlock the loader lock.
                if (lock_loader != nullptr && unlock_loader != nullptr) {
                    unlock_loader(0, loader_magic);
                }

                visit_fn(thread_id, thread, thread_ctx);

                // Lock it again.
                if (lock_loader != nullptr && unlock_loader != nullptr) {
                    loader_magic = 0;
                    lock_loader(0, NULL, &loader_magic);
                }
            }

            ++num_threads_frozen;
        }

        first_run = false;
    } while (num_threads_frozen != 0);

    // Unlock the loader lock.
    if (lock_loader != nullptr && unlock_loader != nullptr) {
        unlock_loader(0, loader_magic);
    }

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

void fix_ip(CONTEXT& ctx, uint8_t* old_ip, uint8_t* new_ip) {
#ifdef _M_X64
    auto ip = ctx.Rip;
#else
    auto ip = ctx.Eip;
#endif

    if (ip == reinterpret_cast<uintptr_t>(old_ip)) {
        ip = reinterpret_cast<uintptr_t>(new_ip);
    }

#ifdef _M_X64
    ctx.Rip = ip;
#else
    ctx.Eip = ip;
#endif
}
} // namespace safetyhook