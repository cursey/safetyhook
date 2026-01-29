module;

#include <safetyhook.hpp>

export module safetyhook;

export {
    namespace safetyhook {

    // allocator.hpp
    using safetyhook::Allocation;
    using safetyhook::Allocator;

    // context.hpp
    using safetyhook::Context;
    using safetyhook::Context32;
    using safetyhook::Context64;
    using safetyhook::Xmm;

    // easy.hpp
    using safetyhook::create_inline;
    using safetyhook::create_mid;
    using safetyhook::create_vm;
    using safetyhook::create_vmt;

    // inline_hook.hpp
    using safetyhook::InlineHook;

    // mid_hook.hpp
    using safetyhook::MidHook;
    using safetyhook::MidHookFn;

    // os.hpp
    using safetyhook::fix_ip;
    using safetyhook::OsError;
    using safetyhook::system_info;
    using safetyhook::SystemInfo;
    using safetyhook::ThreadContext;
    using safetyhook::trap_threads;
    using safetyhook::VM_ACCESS_R;
    using safetyhook::VM_ACCESS_RW;
    using safetyhook::VM_ACCESS_RWX;
    using safetyhook::VM_ACCESS_RX;
    using safetyhook::vm_allocate;
    using safetyhook::vm_is_executable;
    using safetyhook::vm_is_readable;
    using safetyhook::vm_is_writable;
    using safetyhook::vm_protect;
    using safetyhook::vm_query;
    using safetyhook::VmAccess;
    using safetyhook::VmBasicInfo;

    // utility.hpp
    using safetyhook::address_cast;
    using safetyhook::align_down;
    using safetyhook::align_up;
    using safetyhook::is_executable;
    using safetyhook::store;
    using safetyhook::unprotect;
    using safetyhook::UnprotectMemory;

    // vmt_hook.hpp
    using safetyhook::VmHook;
    using safetyhook::VmtHook;

    } // namespace safetyhook

    // safetyhook.hpp
    using ::SafetyHookContext;
    using ::SafetyHookInline;
    using ::SafetyHookMid;
    using ::SafetyHookVm;
    using ::SafetyHookVmt;
}
