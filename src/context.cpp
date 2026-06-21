#include "safetyhook/context.hpp"

#include <array>
#include <cstring>
#include <memory>
#include <mutex>

#include "safetyhook/os.hpp"

namespace safetyhook {

#if SAFETYHOOK_ARCH_X86_32

#if defined(__LDBL_MANT_DIG__) && __LDBL_MANT_DIG__ == 64
// GCC/Clang: long double is 80-bit, bit-identical to Fpu::raw.
// Compiler emits fld/fstp tbyte; no stubs needed.

long double Fpu::as_f80() const noexcept {
    long double result{};
    std::memcpy(&result, raw, 10);

    return result;
}

void Fpu::set_f80(long double value) noexcept {
    std::memcpy(raw, &value, 10);
}

double Fpu::as_f64() const noexcept {
    return static_cast<double>(as_f80());
}

void Fpu::set_f64(double value) noexcept {
    set_f80(static_cast<long double>(value));
}

float Fpu::as_f32() const noexcept {
    return static_cast<float>(as_f64());
}

void Fpu::set_f32(float value) noexcept {
    set_f64(static_cast<double>(value));
}

#else

// MSVC: long double == double, so no f80. Two __cdecl stubs bounce through the FPU; f32 routes through f64.
using FpuToDoubleFn = void (*)(const Fpu* fpu, double& dest) noexcept;
using DoubleToFpuFn = void (*)(double value, Fpu* fpu) noexcept;

struct VmDeleter {
    void operator()(uint8_t* address) const noexcept {
        if (address != nullptr) {
            vm_free(address);
        }
    }
};

struct ConverterCode {
    FpuToDoubleFn fpu_to_double{};
    DoubleToFpuFn double_to_fpu{};
    std::unique_ptr<uint8_t, VmDeleter> memory{};
};

// __cdecl stubs (24 bytes total): fpu_to_double then double_to_fpu.
// clang-format off
constexpr std::array<uint8_t, 24> CONVERTER_CODE{{
    // fpu_to_double(const Fpu* fpu, double& dest)
    0x8B, 0x44, 0x24, 0x04, // mov eax, [esp+4]
    0xDB, 0x28,             // fld tbyte [eax]
    0x8B, 0x44, 0x24, 0x08, // mov eax, [esp+8]
    0xDD, 0x18,             // fstp qword [eax]
    0xC3,                   // ret

    // double_to_fpu(double value, Fpu* fpu)
    0xDD, 0x44, 0x24, 0x04, // fld qword [esp+4]
    0x8B, 0x44, 0x24, 0x0C, // mov eax, [esp+12]
    0xDB, 0x38,             // fstp tbyte [eax]
    0xC3,                   // ret
}};
// clang-format on

ConverterCode make_converter_code() {
    auto mem = vm_allocate(nullptr, CONVERTER_CODE.size(), VM_ACCESS_RWX);
    if (!mem) {
        return {};
    }

    auto* code = mem.value();
    std::memcpy(code, CONVERTER_CODE.data(), CONVERTER_CODE.size());

    ConverterCode result{};
    result.fpu_to_double = reinterpret_cast<FpuToDoubleFn>(code);
    result.double_to_fpu = reinterpret_cast<DoubleToFpuFn>(code + 13);
    result.memory = std::unique_ptr<uint8_t, VmDeleter>(code);

    return result;
}

ConverterCode& get_converter_code() {
    static std::once_flag flag{};
    static ConverterCode code{};

    std::call_once(flag, []() { code = make_converter_code(); });

    return code;
}

float Fpu::as_f32() const noexcept {
    return static_cast<float>(as_f64());
}

double Fpu::as_f64() const noexcept {
    auto& code = get_converter_code();
    if (code.fpu_to_double == nullptr) {
        return 0.0;
    }

    double result{};
    code.fpu_to_double(this, result);

    return result;
}

void Fpu::set_f32(float value) noexcept {
    set_f64(value);
}

void Fpu::set_f64(double value) noexcept {
    auto& code = get_converter_code();
    if (code.double_to_fpu == nullptr) {
        return;
    }

    code.double_to_fpu(value, this);
}

#endif

void Context32::st_pop() noexcept {
    std::memmove(&st0, &st1, sizeof(Fpu) * 7);
    std::memset(&st7, 0, sizeof(Fpu));
}

void Context32::st_push_f32(float value) noexcept {
    std::memmove(&st1, &st0, sizeof(Fpu) * 7);

    st0.set_f32(value);
}

void Context32::st_push_f64(double value) noexcept {
    std::memmove(&st1, &st0, sizeof(Fpu) * 7);

    st0.set_f64(value);
}

#endif // SAFETYHOOK_ARCH_X86_32

} // namespace safetyhook
