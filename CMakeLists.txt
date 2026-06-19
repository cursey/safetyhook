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

set(CMAKE_CXX_EXTENSIONS OFF)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

set(CPM_DOWNLOAD_VERSION 0.40.8)
set(CPM_DOWNLOAD_LOCATION "${CMAKE_CURRENT_BINARY_DIR}/cmake/CPM_${CPM_DOWNLOAD_VERSION}.cmake")

if(NOT EXISTS "${CPM_DOWNLOAD_LOCATION}")
    file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/cmake")
    file(DOWNLOAD
        "https://github.com/cpm-cmake/CPM.cmake/releases/download/v${CPM_DOWNLOAD_VERSION}/CPM.cmake"
        "${CPM_DOWNLOAD_LOCATION}"
        EXPECTED_HASH SHA256=78ba32abdf798bc616bab7c73aac32a17bbd7b06ad9e26a6add69de8f3ae4791
    )
endif()

include("${CPM_DOWNLOAD_LOCATION}")

if(SAFETYHOOK_FETCH_ZYDIS)
    set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
    set(ZYDIS_BUILD_DOXYGEN OFF CACHE BOOL "" FORCE)

    CPMAddPackage(
        NAME Zydis
        GITHUB_REPOSITORY zyantific/zydis
        GIT_TAG v4.1.0
        EXCLUDE_FROM_ALL YES
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
endif()

if(SAFETYHOOK_BUILD_TEST)
    enable_testing()

    CPMAddPackage(
        NAME googletest
        GITHUB_REPOSITORY google/googletest
        GIT_TAG v1.15.2
        OPTIONS
            "gtest_force_shared_crt ON"
            "INSTALL_GTEST OFF"
            "BUILD_GMOCK OFF"
        EXCLUDE_FROM_ALL YES
    )

    CPMAddPackage(
        NAME xbyak
        GITHUB_REPOSITORY herumi/xbyak
        GIT_TAG v7.30
        EXCLUDE_FROM_ALL YES
    )
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
