add_library(safetyhook-module STATIC)
add_library(safetyhook::safetyhook-module ALIAS safetyhook-module)

target_link_libraries(safetyhook-module PUBLIC safetyhook::safetyhook)
target_sources(safetyhook-module
    PUBLIC
        FILE_SET CXX_MODULES
        FILES safetyhook.cppm
)
