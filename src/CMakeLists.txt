add_library(safetyhook
    allocator.cpp
    easy.cpp
    inline_hook.cpp
    mid_hook.cpp
    os.linux.cpp
    os.windows.cpp
    utility.cpp
    vmt_hook.cpp
)
add_library(safetyhook::safetyhook ALIAS safetyhook)

target_compile_features(safetyhook PUBLIC cxx_std_23)
target_include_directories(safetyhook
    PUBLIC
        "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>"
        "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
)
target_link_libraries(safetyhook PUBLIC Zydis)

if(BUILD_SHARED_LIBS)
    target_compile_definitions(safetyhook
        PUBLIC SAFETYHOOK_SHARED_LIB
        PRIVATE SAFETYHOOK_BUILDING
    )
endif()

if(SAFETYHOOK_USE_CXXMODULES)
    target_compile_definitions(safetyhook INTERFACE SAFETYHOOK_USE_CXXMODULES)
endif()

if(WIN32)
    target_compile_definitions(safetyhook PRIVATE NOMINMAX=1)
endif()

safetyhook_enable_strict_warnings(safetyhook PRIVATE)
