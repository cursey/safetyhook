#pragma once

#include <safetyhook.hpp>

#include <memory>

namespace safetyhook::test {
struct SingleInterface {
    virtual ~SingleInterface() = default;
    virtual int add_42(int a) = 0;
};

struct SingleTarget : SingleInterface {
    SAFETYHOOK_NOINLINE int add_42(int a) override { return a + 42; }
};

struct DualInterface {
    virtual ~DualInterface() = default;
    virtual int add_42(int a) = 0;
    virtual int add_43(int a) = 0;
};

struct DualTarget : DualInterface {
    SAFETYHOOK_NOINLINE int add_42(int a) override { return a + 42; }
    SAFETYHOOK_NOINLINE int add_43(int a) override { return a + 43; }
};

struct CastBase1 {
    virtual ~CastBase1() = default;
    virtual int add_42(int a) = 0;
};

struct CastBase2 {
    virtual ~CastBase2() = default;
    virtual int add_1337(int a) = 0;
};

struct CastTarget : CastBase1, CastBase2 {
    SAFETYHOOK_NOINLINE int add_42(int a) override { return a + 42; }
    SAFETYHOOK_NOINLINE int add_1337(int a) override { return a + 1337; }
};

std::unique_ptr<SingleInterface> make_single_target();
std::unique_ptr<DualInterface> make_dual_target();
std::unique_ptr<CastTarget> make_cast_target();
} // namespace safetyhook::test
