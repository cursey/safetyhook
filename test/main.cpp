#include <boost/ut.hpp>

void register_allocator_tests();
void register_inline_hook_tests();
void register_inline_hook_x64_tests();
void register_mid_hook_tests();
void register_vmt_hook_tests();

int main() {
    register_allocator_tests();
    register_inline_hook_tests();
    register_inline_hook_x64_tests();
    register_mid_hook_tests();
    register_vmt_hook_tests();

    return boost::ut::cfg<>.run({.report_errors = true}) ? 1 : 0;
}
