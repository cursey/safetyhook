#include <Windows.h>

#include <safetyhook.hpp>

SafetyHookInline g_PeekMessageA_hook{};
SafetyHookInline g_PeekMessageW_hook{};

BOOL WINAPI hooked_PeekMessageA(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax, UINT wRemoveMsg)
{
    OutputDebugString("hooked_PeekMessageA\n");
    return g_PeekMessageA_hook.stdcall<BOOL>(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax, wRemoveMsg);
}

BOOL WINAPI hooked_PeekMessageW(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax, UINT wRemoveMsg)
{
    OutputDebugString("hooked_PeekMessageW\n");
    return g_PeekMessageW_hook.stdcall<BOOL>(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax, wRemoveMsg);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        g_PeekMessageA_hook = safetyhook::create_inline(&PeekMessageA, &hooked_PeekMessageA);
        g_PeekMessageW_hook = safetyhook::create_inline(&PeekMessageW, &hooked_PeekMessageW);
        break;

    case DLL_PROCESS_DETACH:
        g_PeekMessageW_hook.reset();
        g_PeekMessageA_hook.reset();
        break;
    }
    return TRUE;
}