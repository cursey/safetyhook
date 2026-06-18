#include <array>
#include <cstring>
#include <memory>
#include <mutex>

#include "safetyhook/os.hpp"

#include "safetyhook/context.hpp"

namespace safetyhook {

#if SAFETYHOOK_ARCH_X86_32

using FpuToFloatFn = void (*)(const Fpu* fpu, float& dest) noexcept;
using FloatToFpuFn = void (*)(float value, Fpu* fpu) noexcept;
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
    FpuToFloatFn fpu_to_float{};
    FloatToFpuFn float_to_fpu{};
    FpuToDoubleFn fpu_to_double{};
    DoubleToFpuFn double_to_fpu{};
    std::unique_ptr<uint8_t, VmDeleter> memory{};
};

// Cdecl stubs for converting between Fpu (80-bit x87 extended) and float/double.
constexpr std::array<uint8_t, 48> CONVERTER_CODE{{
    // fpu_to_float(const Fpu* fpu, float& dest):
    0x8B, 0x44, 0x24, 0x04, // mov eax, [esp+4]
    0xDB, 0x28,             // fld tbyte ptr [eax]
    0x8B, 0x44, 0x24, 0x08, // mov eax, [esp+8]
    0xD9, 0x18,             // fstp dword ptr [eax]
    0xC3,                   // ret

    // float_to_fpu(float value, Fpu* fpu):
    0xD9, 0x44, 0x24, 0x04, // fld dword ptr [esp+4]
    0x8B, 0x44, 0x24, 0x08, // mov eax, [esp+8]
    0xDB, 0x38,             // fstp tbyte ptr [eax]
    0xC3,                   // ret

    // fpu_to_double(const Fpu* fpu, double& dest):
    0x8B, 0x44, 0x24, 0x04, // mov eax, [esp+4]
    0xDB, 0x28,             // fld tbyte ptr [eax]
    0x8B, 0x44, 0x24, 0x08, // mov eax, [esp+8]
    0xDD, 0x18,             // fstp qword ptr [eax]
    0xC3,                   // ret

    // double_to_fpu(double value, Fpu* fpu):
    0xDD, 0x44, 0x24, 0x04, // fld qword ptr [esp+4]
    0x8B, 0x44, 0x24, 0x0C, // mov eax, [esp+12]
    0xDB, 0x38,             // fstp tbyte ptr [eax]
    0xC3                    // ret
}};

ConverterCode make_converter_code() {
    auto mem = vm_allocate(nullptr, CONVERTER_CODE.size(), VM_ACCESS_RWX);
    if (!mem) {
        return {};
    }

    auto* code = mem.value();
    std::memcpy(code, CONVERTER_CODE.data(), CONVERTER_CODE.size());

    ConverterCode result{};
    result.fpu_to_float = reinterpret_cast<FpuToFloatFn>(code);
    result.float_to_fpu = reinterpret_cast<FloatToFpuFn>(code + 13);
    result.fpu_to_double = reinterpret_cast<FpuToDoubleFn>(code + 24);
    result.double_to_fpu = reinterpret_cast<DoubleToFpuFn>(code + 37);
    result.memory.reset(code);

    return result;
}

ConverterCode& get_converter_code() {
    static std::once_flag flag{};
    static ConverterCode code{};

    std::call_once(flag, []() { code = make_converter_code(); });

    return code;
}

float Fpu::as_f32() const noexcept {
    auto& code = get_converter_code();
    if (code.fpu_to_float == nullptr) {
        return 0.0f;
    }

    float result{};
    code.fpu_to_float(this, result);

    return result;
}

void Fpu::set_f32(float value) noexcept {
    auto& code = get_converter_code();
    if (code.float_to_fpu == nullptr) {
        return;
    }

    code.float_to_fpu(value, this);
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

void Fpu::set_f64(double value) noexcept {
    auto& code = get_converter_code();
    if (code.double_to_fpu == nullptr) {
        return;
    }

    code.double_to_fpu(value, this);
}

#else

float Fpu::as_f32() const noexcept {
    return 0.0f;
}

void Fpu::set_f32(float) noexcept {
}

double Fpu::as_f64() const noexcept {
    return 0.0;
}

void Fpu::set_f64(double) noexcept {
}

#endif

} // namespace safetyhook
