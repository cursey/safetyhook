#pragma once

#if defined(_MSC_VER)
#define SAFETYHOOK_COMPILER_MSVC 1
#define SAFETYHOOK_COMPILER_GCC 0
#define SAFETYHOOK_COMPILER_CLANG 0
#elif defined(__GNUC__)
#define SAFETYHOOK_COMPILER_MSVC 0
#define SAFETYHOOK_COMPILER_GCC 1
#define SAFETYHOOK_COMPILER_CLANG 0
#elif defined(__clang__)
#define SAFETYHOOK_COMPILER_MSVC 0
#define SAFETYHOOK_COMPILER_GCC 0
#define SAFETYHOOK_COMPILER_CLANG 1
#else
#error "Unsupported compiler"
#endif

#if SAFETYHOOK_COMPILER_MSVC
#if defined(_M_IX86)
#define SAFETYHOOK_ARCH_X86_32 1
#define SAFETYHOOK_ARCH_X86_64 0
#elif defined(_M_X64)
#define SAFETYHOOK_ARCH_X86_32 0
#define SAFETYHOOK_ARCH_X86_64 1
#else
#error "Unsupported architecture"
#endif
#elif SAFETYHOOK_COMPILER_GCC || SAFETYHOOK_COMPILER_CLANG
#if defined(__i386__)
#define SAFETYHOOK_ARCH_X86_32 1
#define SAFETYHOOK_ARCH_X86_64 0
#elif defined(__x86_64__)
#define SAFETYHOOK_ARCH_X86_32 0
#define SAFETYHOOK_ARCH_X86_64 1
#else
#error "Unsupported architecture"
#endif
#endif
