function(add_safetyhook_example target source)
    add_executable(${target} "${source}")
    target_compile_features(${target} PRIVATE cxx_std_23)
    target_link_libraries(${target}
        PRIVATE
            safetyhook::safetyhook
            "$<$<AND:$<CXX_COMPILER_ID:GNU>,$<BOOL:${MINGW}>>:stdc++exp>"
    )
    safetyhook_enable_strict_warnings(${target} PRIVATE)
endfunction()

add_safetyhook_example(example-minimal minimal.cpp)
add_safetyhook_example(example-multiple multiple.cpp)
add_safetyhook_example(example-midhook midhook.cpp)
add_safetyhook_example(example-threadsafe threadsafe.cpp)
add_safetyhook_example(example-vmthook vmthook.cpp)

if(WIN32)
    add_library(example-dll SHARED dll.cpp)
    target_compile_features(example-dll PUBLIC cxx_std_23)
    target_link_libraries(example-dll PUBLIC safetyhook::safetyhook)
    safetyhook_enable_strict_warnings(example-dll PRIVATE)
endif()

if(SAFETYHOOK_BUILD_MODULE)
    add_safetyhook_example(example-module module.cpp)
    target_link_libraries(example-module PRIVATE safetyhook::safetyhook-module)
    set_target_properties(example-module PROPERTIES CXX_SCAN_FOR_MODULES ON)
endif()
