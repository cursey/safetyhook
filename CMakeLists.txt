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

set(CPM_DOWNLOAD_VERSION 0.42.3)
set(CPM_HASH_SUM "a609e875fd532b067174250f6abbc3dac22fe2d64869783fb1e80bda1625c844")

if(CPM_SOURCE_CACHE)
    set(CPM_DOWNLOAD_LOCATION "${CPM_SOURCE_CACHE}/cpm/CPM_${CPM_DOWNLOAD_VERSION}.cmake")
elseif(DEFINED ENV{CPM_SOURCE_CACHE})
    set(CPM_DOWNLOAD_LOCATION "$ENV{CPM_SOURCE_CACHE}/cpm/CPM_${CPM_DOWNLOAD_VERSION}.cmake")
else()
    set(CPM_DOWNLOAD_LOCATION "${CMAKE_BINARY_DIR}/cmake/CPM_${CPM_DOWNLOAD_VERSION}.cmake")
endif()

get_filename_component(CPM_DOWNLOAD_LOCATION "${CPM_DOWNLOAD_LOCATION}" ABSOLUTE)

cmake_path(GET CPM_DOWNLOAD_LOCATION PARENT_PATH CPM_DOWNLOAD_DIR)
file(MAKE_DIRECTORY "${CPM_DOWNLOAD_DIR}")

if(NOT EXISTS "${CPM_DOWNLOAD_LOCATION}")
    file(DOWNLOAD
        "https://github.com/cpm-cmake/CPM.cmake/releases/download/v${CPM_DOWNLOAD_VERSION}/CPM.cmake"
        "${CPM_DOWNLOAD_LOCATION}"
        EXPECTED_HASH SHA256=${CPM_HASH_SUM}
    )
endif()

include("${CPM_DOWNLOAD_LOCATION}")

if(SAFETYHOOK_FETCH_ZYDIS)
    # CPM.cmake shorthand syntax will add `EXCLUDE_FROM_ALL` and `SYSTEM` flag by default.
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
endif()

if(SAFETYHOOK_BUILD_TEST)
    enable_testing()

    CPMAddPackage("gh:boost-ext/ut@2.3.1")

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
