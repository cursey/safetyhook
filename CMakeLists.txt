cmake_minimum_required(VERSION 3.28)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
    message(FATAL_ERROR "In-tree builds are not supported. Run CMake from a separate directory: cmake -B build")
endif()

project(safetyhook LANGUAGES C CXX)

option(SAFETYHOOK_BUILD_DOCS "Build documentation" OFF)
option(SAFETYHOOK_BUILD_TEST "Build tests" OFF)
option(SAFETYHOOK_BUILD_EXAMPLES "Build examples" OFF)
option(SAFETYHOOK_AMALGAMATE "Build the amalgamated source" OFF)
option(SAFETYHOOK_FETCH_ZYDIS "Fetch Zydis with CPM" ON)
option(SAFETYHOOK_USE_CXXMODULES "Expose the C++ module define to consumers" OFF)
option(SAFETYHOOK_BUILD_MODULE "Build the C++ module target" OFF)

if(DEFINED ENV{CI})
    set(SAFETYHOOK_WARNINGS_AS_ERRORS_DEFAULT ON)
else()
    set(SAFETYHOOK_WARNINGS_AS_ERRORS_DEFAULT OFF)
endif()
option(SAFETYHOOK_WARNINGS_AS_ERRORS "Treat warnings as errors" ${SAFETYHOOK_WARNINGS_AS_ERRORS_DEFAULT})

set(CMAKE_CXX_EXTENSIONS OFF)

function(safetyhook_enable_strict_warnings target scope)
    if(MSVC OR CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")
        target_compile_options(${target} ${scope} /W4 /permissive-)
        if(SAFETYHOOK_WARNINGS_AS_ERRORS)
            target_compile_options(${target} ${scope} /WX)
        endif()
    elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
        target_compile_options(${target} ${scope} -Wall -Wextra -Wpedantic)
        if(SAFETYHOOK_WARNINGS_AS_ERRORS)
            target_compile_options(${target} ${scope} -Werror)
        endif()
    endif()
endfunction()

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(cmake/CPM.cmake)

# CPM.cmake shorthand syntax will add `EXCLUDE_FROM_ALL` and `SYSTEM` flag by default.

if(SAFETYHOOK_FETCH_ZYDIS)
    CPMAddPackage(
        URI "gh:zyantific/zydis@4.1.0"
        OPTIONS
            "ZYDIS_BUILD_EXAMPLES OFF"
            "ZYDIS_BUILD_TOOLS OFF"
            "ZYDIS_BUILD_DOXYGEN OFF"
            "ZYDIS_BUILD_TESTS OFF"
    )
else()
    find_package(Zydis REQUIRED CONFIG)
endif()

if(TARGET Zydis::Zydis AND NOT TARGET Zydis)
    add_library(Zydis ALIAS Zydis::Zydis)
endif()

if(SAFETYHOOK_BUILD_DOCS)
    find_package(Doxygen REQUIRED)
endif()

if(SAFETYHOOK_AMALGAMATE)
    find_package(Python3 REQUIRED)
    set(SAFETYHOOK_AMALGAMATED_DIR "${PROJECT_BINARY_DIR}/amalgamated-dist")
endif()

if(SAFETYHOOK_BUILD_TEST)
    enable_testing()

    CPMAddPackage(
        URI "gh:google/googletest@1.17.0"
        OPTIONS
            "BUILD_GMOCK OFF"
            "INSTALL_GTEST OFF"
            "gtest_force_shared_crt ON"
    )

    CPMAddPackage("gh:herumi/xbyak@7.37.3")
endif()

add_subdirectory(src)

if(SAFETYHOOK_BUILD_MODULE)
    add_subdirectory(module)
endif()

configure_package_config_file(
    cmake/safetyhook-config.cmake.in
    "${PROJECT_BINARY_DIR}/safetyhook-config.cmake"
    INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/safetyhook"
)

install(
    TARGETS safetyhook
    EXPORT safetyhook-targets
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
    INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)

if(SAFETYHOOK_BUILD_MODULE)
    install(
        TARGETS safetyhook-module
        EXPORT safetyhook-targets
        LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
        INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
        FILE_SET CXX_MODULES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/safetyhook"
    )
endif()

install(DIRECTORY include/ DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

install(
    EXPORT safetyhook-targets
    FILE safetyhook-targets.cmake
    NAMESPACE safetyhook::
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/safetyhook"
)

install(
    FILES "${PROJECT_BINARY_DIR}/safetyhook-config.cmake"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/safetyhook"
)

if(SAFETYHOOK_BUILD_DOCS)
    add_subdirectory(docs)
endif()

if(SAFETYHOOK_AMALGAMATE)
    add_subdirectory(cmake/amalgamation)
endif()

if(SAFETYHOOK_BUILD_EXAMPLES)
    add_subdirectory(example)
endif()

if(SAFETYHOOK_BUILD_TEST)
    add_subdirectory(test)
endif()
