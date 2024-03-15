#include "safetyhook/common.hpp"

#if SAFETYHOOK_OS_WINDOWS

#define NOMINMAX
#if __has_include(<Windows.h>)
#include <Windows.h>
#elif __has_include(<windows.h>)
#include <windows.h>
#else
#error "Windows.h not found"
#endif

#include <winternl.h>

#include "safetyhook/os.hpp"

#pragma comment(lib, "ntdll")

extern "C" {
NTSTATUS
NTAPI
NtGetNextThread(HANDLE ProcessHandle, HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes,
    ULONG Flags, PHANDLE NewThreadHandle);
}

namespace safetyhook {
std::expected<uint8_t*, OsError> vm_allocate(uint8_t* address, size_t size, VmAccess access) {
    DWORD protect = 0;

    if (access == VM_ACCESS_R) {
        protect = PAGE_READONLY;
    } else if (access == VM_ACCESS_RW) {
        protect = PAGE_READWRITE;
    } else if (access == VM_ACCESS_RX) {
        protect = PAGE_EXECUTE_READ;
    } else if (access == VM_ACCESS_RWX) {
        protect = PAGE_EXECUTE_READWRITE;
    } else {
        return std::unexpected{OsError::FAILED_TO_ALLOCATE};
    }

    auto* result = VirtualAlloc(address, size, MEM_COMMIT | MEM_RESERVE, protect);

    if (result == nullptr) {
        return std::unexpected{OsError::FAILED_TO_ALLOCATE};
    }

    return static_cast<uint8_t*>(result);
}

void vm_free(uint8_t* address) {
    VirtualFree(address, 0, MEM_RELEASE);
}

std::expected<uint32_t, OsError> vm_protect(uint8_t* address, size_t size, VmAccess access) {
    DWORD protect = 0;

    if (access == VM_ACCESS_R) {
        protect = PAGE_READONLY;
    } else if (access == VM_ACCESS_RW) {
        protect = PAGE_READWRITE;
    } else if (access == VM_ACCESS_RX) {
        protect = PAGE_EXECUTE_READ;
    } else if (access == VM_ACCESS_RWX) {
        protect = PAGE_EXECUTE_READWRITE;
    } else {
        return std::unexpected{OsError::FAILED_TO_PROTECT};
    }

    return vm_protect(address, size, protect);
}

std::expected<uint32_t, OsError> vm_protect(uint8_t* address, size_t size, uint32_t protect) {
    DWORD old_protect = 0;

    if (VirtualProtect(address, size, protect, &old_protect) == FALSE) {
        return std::unexpected{OsError::FAILED_TO_PROTECT};
    }

    return old_protect;
}

std::expected<VmBasicInfo, OsError> vm_query(uint8_t* address) {
    MEMORY_BASIC_INFORMATION mbi{};
    auto result = VirtualQuery(address, &mbi, sizeof(mbi));

    if (result == 0) {
        return std::unexpected{OsError::FAILED_TO_QUERY};
    }

    VmAccess access{
        .read = (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) != 0,
        .write = (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)) != 0,
        .execute = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) != 0,
    };

    return VmBasicInfo{
        .address = static_cast<uint8_t*>(mbi.AllocationBase),
        .size = mbi.RegionSize,
        .access = access,
        .is_free = mbi.State == MEM_FREE,
    };
}

bool vm_is_readable(uint8_t* address, size_t size) {
    return IsBadReadPtr(address, size) == FALSE;
}

bool vm_is_writable(uint8_t* address, size_t size) {
    return IsBadWritePtr(address, size) == FALSE;
}

bool vm_is_executable(uint8_t* address) {
    LPVOID image_base_ptr;

    if (RtlPcToFileHeader(address, &image_base_ptr) == nullptr) {
        return vm_query(address).value_or(VmBasicInfo{}).access.execute;
    }

    // Just check if the section is executable.
    const auto* image_base = reinterpret_cast<uint8_t*>(image_base_ptr);
    const auto* dos_hdr = reinterpret_cast<const IMAGE_DOS_HEADER*>(image_base);

    if (dos_hdr->e_magic != IMAGE_DOS_SIGNATURE) {
        return vm_query(address).value_or(VmBasicInfo{}).access.execute;
    }

    const auto* nt_hdr = reinterpret_cast<const IMAGE_NT_HEADERS*>(image_base + dos_hdr->e_lfanew);

    if (nt_hdr->Signature != IMAGE_NT_SIGNATURE) {
        return vm_query(address).value_or(VmBasicInfo{}).access.execute;
    }

    const auto* section = IMAGE_FIRST_SECTION(nt_hdr);

    for (auto i = 0; i < nt_hdr->FileHeader.NumberOfSections; ++i, ++section) {
        if (address >= image_base + section->VirtualAddress &&
            address < image_base + section->VirtualAddress + section->Misc.VirtualSize) {
            return (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        }
    }

    return vm_query(address).value_or(VmBasicInfo{}).access.execute;
}

SystemInfo system_info() {
    SystemInfo info{};

    SYSTEM_INFO si{};
    GetSystemInfo(&si);

    info.page_size = si.dwPageSize;
    info.allocation_granularity = si.dwAllocationGranularity;
    info.min_address = static_cast<uint8_t*>(si.lpMinimumApplicationAddress);
    info.max_address = static_cast<uint8_t*>(si.lpMaximumApplicationAddress);

    return info;
}

void execute_while_frozen(
    const std::function<void()>& run_fn, const std::function<void(ThreadId, ThreadHandle, ThreadContext)>& visit_fn) {
    // Freeze all threads.
    int num_threads_frozen;
    auto first_run = true;

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
                visit_fn(static_cast<ThreadId>(thread_id), static_cast<ThreadHandle>(thread),
                    static_cast<ThreadContext>(&thread_ctx));
            }

            SetThreadContext(thread, &thread_ctx);

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

#endif