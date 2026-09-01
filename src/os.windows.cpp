#include <map>
#include <memory>
#include <mutex>

#include "safetyhook/common.hpp"
#include "safetyhook/utility.hpp"

#if SAFETYHOOK_OS_WINDOWS

#ifndef NOMINMAX
#define NOMINMAX
#endif

#if __has_include(<Windows.h>)
#include <Windows.h>
#elif __has_include(<windows.h>)
#include <windows.h>
#else
#error "Windows.h not found"
#endif

#include "safetyhook/os.hpp"

#if SAFETYHOOK_USE_NT_API

#include <winternl.h>

namespace {
inline HANDLE nt_current_process() {
    return reinterpret_cast<HANDLE>(static_cast<intptr_t>(-1));
}

// clang-format off
using NtAllocateVirtualMemory_t =
    NTSTATUS NTAPI(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        ULONG_PTR ZeroBits,
        PSIZE_T RegionSize,
        ULONG AllocationType,
        ULONG Protect
    );
using NtFreeVirtualMemory_t =
    NTSTATUS NTAPI(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        PSIZE_T RegionSize,
        ULONG FreeType
    );
using NtProtectVirtualMemory_t =
    NTSTATUS NTAPI(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        PSIZE_T RegionSize,
        ULONG NewProtect,
        PULONG OldProtect
    );
using NtQueryVirtualMemory_t =
    NTSTATUS NTAPI(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        ULONG MemoryInformationClass,
        PVOID MemoryInformation,
        SIZE_T MemoryInformationLength,
        PSIZE_T ReturnLength
    );
using RtlAddVectoredExceptionHandler_t =
    PVOID NTAPI(
        ULONG FirstHandler,
        PVECTORED_EXCEPTION_HANDLER VectoredHandler
    );
using RtlRemoveVectoredExceptionHandler_t =
    ULONG NTAPI(
        PVOID VectoredHandlerHandle
    );
// clang-format on

// MemoryBasicInformation class for NtQueryVirtualMemory.
constexpr ULONG NT_MEMORY_BASIC_INFORMATION = 0;

struct NtApi {
    NtAllocateVirtualMemory_t* allocate;
    NtFreeVirtualMemory_t* free;
    NtProtectVirtualMemory_t* protect;
    NtQueryVirtualMemory_t* query;
    RtlAddVectoredExceptionHandler_t* add_veh;
    RtlRemoveVectoredExceptionHandler_t* remove_veh;
};

// GetProcAddress returns a generic FARPROC; reinterpreting it to the concrete
// ntdll export type is the standard idiom here.
template <typename T> T resolve(HMODULE module, const char* name) {
    return reinterpret_cast<T>(reinterpret_cast<void*>(GetProcAddress(module, name)));
}

// Lazily resolved once; ntdll is always present in a live process.
const NtApi& nt() {
    static const NtApi api = [] {
        NtApi a{};

        if (auto* ntdll = GetModuleHandleW(L"ntdll.dll")) {
            a.allocate = resolve<NtAllocateVirtualMemory_t*>(ntdll, "NtAllocateVirtualMemory");
            a.free = resolve<NtFreeVirtualMemory_t*>(ntdll, "NtFreeVirtualMemory");
            a.protect = resolve<NtProtectVirtualMemory_t*>(ntdll, "NtProtectVirtualMemory");
            a.query = resolve<NtQueryVirtualMemory_t*>(ntdll, "NtQueryVirtualMemory");
            a.add_veh = resolve<RtlAddVectoredExceptionHandler_t*>(ntdll, "RtlAddVectoredExceptionHandler");
            a.remove_veh = resolve<RtlRemoveVectoredExceptionHandler_t*>(ntdll, "RtlRemoveVectoredExceptionHandler");
        }

        return a;
    }();

    return api;
}
} // namespace
#endif

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

#if SAFETYHOOK_USE_NT_API
    if (nt().allocate == nullptr) {
        return std::unexpected{OsError::FAILED_TO_ALLOCATE};
    }

    PVOID result = address;
    SIZE_T region_size = size;

    if (!NT_SUCCESS(nt().allocate(nt_current_process(), &result, 0, &region_size, MEM_COMMIT | MEM_RESERVE, protect))) {
        return std::unexpected{OsError::FAILED_TO_ALLOCATE};
    }
#else
    auto* result = VirtualAlloc(address, size, MEM_COMMIT | MEM_RESERVE, protect);
#endif

    if (result == nullptr) {
        return std::unexpected{OsError::FAILED_TO_ALLOCATE};
    }

    return static_cast<uint8_t*>(result);
}

void vm_free(uint8_t* address) {
#if SAFETYHOOK_USE_NT_API
    if (nt().free != nullptr) {
        PVOID base = address;
        SIZE_T region_size = 0;
        nt().free(nt_current_process(), &base, &region_size, MEM_RELEASE);
    }
#else
    VirtualFree(address, 0, MEM_RELEASE);
#endif
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

#if SAFETYHOOK_USE_NT_API
    if (nt().protect == nullptr) {
        return std::unexpected{OsError::FAILED_TO_PROTECT};
    }

    PVOID base = address;
    SIZE_T region_size = size;

    if (!NT_SUCCESS(nt().protect(nt_current_process(), &base, &region_size, protect, &old_protect))) {
        return std::unexpected{OsError::FAILED_TO_PROTECT};
    }
#else
    if (VirtualProtect(address, size, protect, &old_protect) == FALSE) {
        return std::unexpected{OsError::FAILED_TO_PROTECT};
    }
#endif

    return old_protect;
}

std::expected<VmBasicInfo, OsError> vm_query(uint8_t* address) {
    MEMORY_BASIC_INFORMATION mbi{};

#if SAFETYHOOK_USE_NT_API
    if (nt().query == nullptr) {
        return std::unexpected{OsError::FAILED_TO_QUERY};
    }

    SIZE_T return_length = 0;

    if (!NT_SUCCESS(nt().query(
            nt_current_process(), address, NT_MEMORY_BASIC_INFORMATION, &mbi, sizeof(mbi), &return_length)) ||
        return_length == 0) {
        return std::unexpected{OsError::FAILED_TO_QUERY};
    }
#else
    if (VirtualQuery(address, &mbi, sizeof(mbi)) == 0) {
        return std::unexpected{OsError::FAILED_TO_QUERY};
    }
#endif

    VmAccess access{};
    access.read = (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) != 0;
    access.write = (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)) != 0;
    access.execute = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) != 0;

    VmBasicInfo info{};
    info.address = static_cast<uint8_t*>(mbi.AllocationBase);
    info.size = mbi.RegionSize;
    info.access = access;
    info.is_free = mbi.State == MEM_FREE;

    return info;
}

bool vm_is_readable(uint8_t* address, size_t size) {
#if SAFETYHOOK_USE_NT_API
    (void)size;
    auto info = vm_query(address);
    return info.has_value() && !info->is_free && info->access.read;
#else
    return IsBadReadPtr(address, size) == FALSE;
#endif
}

bool vm_is_writable(uint8_t* address, size_t size) {
#if SAFETYHOOK_USE_NT_API
    (void)size;
    auto info = vm_query(address);
    return info.has_value() && !info->is_free && info->access.write;
#else
    return IsBadWritePtr(address, size) == FALSE;
#endif
}

bool vm_is_executable(uint8_t* address) {
    // Check if the address is in a valid module allowing us to potentially skip a heavier memory query.
    HMODULE image{};
    if (!GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPTSTR>(address), &image) ||
        image == nullptr) {
        return vm_query(address).value_or(VmBasicInfo{}).access.execute;
    }

    // Just check if the section is executable.
    const auto* image_base = reinterpret_cast<uint8_t*>(image);
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

struct TrapInfo {
    uint8_t* from_page_start;
    uint8_t* from_page_end;
    uint8_t* from;
    uint8_t* to_page_start;
    uint8_t* to_page_end;
    uint8_t* to;
    size_t len;
};

class TrapManager final {
public:
    static std::mutex mutex;
    static std::unique_ptr<TrapManager> instance;
    static bool is_destructed;

    TrapManager() {
#if SAFETYHOOK_USE_NT_API
        m_trap_veh = nt().add_veh != nullptr ? nt().add_veh(1, trap_handler) : nullptr;
#else
        m_trap_veh = AddVectoredExceptionHandler(1, trap_handler);
#endif
    }
    ~TrapManager() {
        if (m_trap_veh != nullptr) {
#if SAFETYHOOK_USE_NT_API
            if (nt().remove_veh != nullptr) {
                nt().remove_veh(m_trap_veh);
            }
#else
            RemoveVectoredExceptionHandler(m_trap_veh);
#endif
        }
        is_destructed = true;
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
        auto search = std::find_if(m_traps.begin(), m_traps.end(), [address](auto& trap) {
            return address >= trap.second.from_page_start && address < trap.second.from_page_end;
        });

        if (search != m_traps.end()) {
            return &search->second;
        }

        search = std::find_if(m_traps.begin(), m_traps.end(), [address](auto& trap) {
            return address >= trap.second.to_page_start && address < trap.second.to_page_end;
        });

        if (search != m_traps.end()) {
            return &search->second;
        }

        return nullptr;
    }

    void add_trap(uint8_t* from, uint8_t* to, size_t len) {
        TrapInfo info{};
        info.from_page_start = align_down(from, 0x1000);
        info.from_page_end = align_up(from + len, 0x1000);
        info.from = from;
        info.to_page_start = align_down(to, 0x1000);
        info.to_page_end = align_up(to + len, 0x1000);
        info.to = to;
        info.len = len;

        m_traps.insert_or_assign(from, std::move(info));
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
bool TrapManager::is_destructed = false;

void find_me() {
}

static std::mutex virtual_protect_mutex;

// Backend-aware wrappers so trap_threads bypasses kernel32 when the Nt API is enabled.
static void trap_query(void* address, MEMORY_BASIC_INFORMATION& mbi) {
#if SAFETYHOOK_USE_NT_API
    SIZE_T return_length = 0;
    if (nt().query != nullptr) {
        nt().query(nt_current_process(), address, NT_MEMORY_BASIC_INFORMATION, &mbi, sizeof(mbi), &return_length);
    }
#else
    VirtualQuery(address, &mbi, sizeof(mbi));
#endif
}

static void trap_protect(void* address, size_t size, DWORD new_protect, DWORD& old_protect) {
#if SAFETYHOOK_USE_NT_API
    if (nt().protect != nullptr) {
        PVOID base = address;
        SIZE_T region_size = size;
        ULONG previous = 0;
        nt().protect(nt_current_process(), &base, &region_size, new_protect, &previous);
        old_protect = previous;
    }
#else
    VirtualProtect(address, size, new_protect, &old_protect);
#endif
}

void trap_threads(uint8_t* from, uint8_t* to, size_t len, const std::function<void()>& run_fn) {
    MEMORY_BASIC_INFORMATION find_me_mbi{};
    MEMORY_BASIC_INFORMATION from_mbi{};
    MEMORY_BASIC_INFORMATION to_mbi{};

    trap_query(reinterpret_cast<void*>(find_me), find_me_mbi);
    trap_query(from, from_mbi);
    trap_query(to, to_mbi);

    if (to_mbi.State != MEM_COMMIT) {
        return;
    }

    auto new_protect = PAGE_READWRITE;

    if (from_mbi.AllocationBase == find_me_mbi.AllocationBase || to_mbi.AllocationBase == find_me_mbi.AllocationBase) {
        new_protect = PAGE_EXECUTE_READWRITE;
    }

    auto si = system_info();
    auto* from_page_start = align_down(from, si.page_size);
    auto* from_page_end = align_up(from + len, si.page_size);
    // Guard the address of the protection function actually used below, so we never
    // remove protection from the very page we are about to call into.
#if SAFETYHOOK_USE_NT_API
    auto* vp_start = reinterpret_cast<uint8_t*>(nt().protect);
#else
    auto* vp_start = reinterpret_cast<uint8_t*>(&VirtualProtect);
#endif
    auto* vp_end = vp_start + 0x20;

    if (!(from_page_end < vp_start || vp_end < from_page_start)) {
        new_protect = PAGE_EXECUTE_READWRITE;
    }

    if (!TrapManager::is_destructed) {
        std::scoped_lock lock{TrapManager::mutex};

        if (TrapManager::instance == nullptr) {
            TrapManager::instance = std::make_unique<TrapManager>();
        }

        TrapManager::instance->add_trap(from, to, len);
    }

    // Make sure we aren't working on a different address in the same memory page on a different thread.
    std::scoped_lock vp_lock{virtual_protect_mutex};

    DWORD from_protect;
    DWORD to_protect;

    trap_protect(from, len, new_protect, from_protect);
    trap_protect(to, len, new_protect, to_protect);

    if (run_fn) {
        run_fn();
    }

    trap_protect(to, len, to_protect, to_protect);
    trap_protect(from, len, from_protect, from_protect);
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
