add_library(safetyhook-module STATIC)
add_library(safetyhook::safetyhook-module ALIAS safetyhook-module)

safetyhook_enable_strict_warnings(safetyhook-module PRIVATE)
target_link_libraries(safetyhook-module PRIVATE safetyhook::safetyhook)
target_sources(safetyhook-module
    PUBLIC
        FILE_SET CXX_MODULES
        FILES safetyhook.cppm
)
