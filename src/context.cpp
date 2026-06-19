#include "safetyhook/context.hpp"

#include <array>
#include <cstring>
#include <memory>
#include <mutex>

#include "safetyhook/os.hpp"

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

// __cdecl stubs that bounce 80-bit extended floats through the FPU via fld/fstp.
// Laid out as four contiguous routines; entry-point offsets are kept in sync with make_converter_code() below.
// clang-format off
constexpr std::array<uint8_t, 48> CONVERTER_CODE{{
    // void fpu_to_float(const Fpu* fpu, float& dest);
    0x8B, 0x44, 0x24, 0x04, // mov eax, [esp+4] ; &fpu
    0xDB, 0x28,             // fld tbyte [eax]  ; ST0 = *fpu (80-bit)
    0x8B, 0x44, 0x24, 0x08, // mov eax, [esp+8] ; &dest
    0xD9, 0x18,             // fstp dword [eax] ; *dest = ST0 (32-bit float)
    0xC3,                   // ret

    // void float_to_fpu(float value, Fpu* fpu);
    0xD9, 0x44, 0x24, 0x04, // fld dword [esp+4] ; ST0 = value
    0x8B, 0x44, 0x24, 0x08, // mov eax, [esp+8]  ; &fpu
    0xDB, 0x38,             // fstp tbyte [eax]  ; *fpu = ST0 (80-bit)
    0xC3,                   // ret

    // void fpu_to_double(const Fpu* fpu, double& dest);
    0x8B, 0x44, 0x24, 0x04, // mov eax, [esp+4] ; &fpu
    0xDB, 0x28,             // fld tbyte [eax]  ; ST0 = *fpu (80-bit)
    0x8B, 0x44, 0x24, 0x08, // mov eax, [esp+8] ; &dest
    0xDD, 0x18,             // fstp qword [eax] ; *dest = ST0 (64-bit double)
    0xC3,                   // ret

    // void double_to_fpu(double value, Fpu* fpu);
    0xDD, 0x44, 0x24, 0x04, // fld qword [esp+4] ; ST0 = value (8-byte double at [esp+4..12])
    0x8B, 0x44, 0x24, 0x0C, // mov eax, [esp+12] ; &fpu
    0xDB, 0x38,             // fstp tbyte [eax]  ; *fpu = ST0 (80-bit)
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
    result.fpu_to_float = reinterpret_cast<FpuToFloatFn>(code + 0);
    result.float_to_fpu = reinterpret_cast<FloatToFpuFn>(code + 13);
    result.fpu_to_double = reinterpret_cast<FpuToDoubleFn>(code + 24);
    result.double_to_fpu = reinterpret_cast<DoubleToFpuFn>(code + 37);
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
    auto& code = get_converter_code();
    if (code.fpu_to_float == nullptr) {
        return 0.0f;
    }

    float out{};
    code.fpu_to_float(this, out);

    return out;
}

double Fpu::as_f64() const noexcept {
    auto& code = get_converter_code();
    if (code.fpu_to_double == nullptr) {
        return 0.0;
    }

    double out{};
    code.fpu_to_double(this, out);

    return out;
}

void Fpu::set_f32(float v) noexcept {
    auto& code = get_converter_code();
    if (code.float_to_fpu == nullptr) {
        return;
    }

    code.float_to_fpu(v, this);
}

void Fpu::set_f64(double v) noexcept {
    auto& code = get_converter_code();
    if (code.double_to_fpu == nullptr) {
        return;
    }

    code.double_to_fpu(v, this);
}

void Context32::st_pop() noexcept {
    // Shift ST(1..7) down into ST(0..6).
    std::memmove(&st[0], &st[1], sizeof(Fpu) * 7);

    // Vacated ST(7): clear defensively. The callback's set_f32/set_f64 will rewrite
    // both the value and (implicitly, via FRSTOR replaying the captured env) the tag.
    std::memset(&st[7], 0, sizeof(Fpu));
}

void Context32::st_push_f32(float v) noexcept {
    // Shift ST(0..6) up into ST(1..7), dropping old ST(7).
    std::memmove(&st[1], &st[0], sizeof(Fpu) * 7);

    st[0].set_f32(v);
}

void Context32::st_push_f64(double v) noexcept {
    std::memmove(&st[1], &st[0], sizeof(Fpu) * 7);

    st[0].set_f64(v);
}

#endif // SAFETYHOOK_ARCH_X86_32

} // namespace safetyhook
