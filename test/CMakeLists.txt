set(SAFETYHOOK_TEST_SOURCES
    allocator.cpp
    inline_hook.cpp
    inline_hook.x86_64.cpp
    main.cpp
    mid_hook.cpp
    vmt_hook.cpp
    vmt_targets.cpp
)

add_executable(safetyhook-test ${SAFETYHOOK_TEST_SOURCES})
target_compile_features(safetyhook-test PRIVATE cxx_std_23)
target_link_libraries(safetyhook-test PRIVATE GTest::gtest safetyhook::safetyhook xbyak::xbyak)
safetyhook_enable_strict_warnings(safetyhook-test PRIVATE)
add_test(NAME safetyhook COMMAND $<TARGET_FILE:safetyhook-test>)

if(SAFETYHOOK_AMALGAMATE)
    add_executable(safetyhook-test-amalgamated
        ${SAFETYHOOK_TEST_SOURCES}
        "${SAFETYHOOK_AMALGAMATED_DIR}/safetyhook.cpp"
    )
    target_compile_features(safetyhook-test-amalgamated PRIVATE cxx_std_23)
    target_include_directories(safetyhook-test-amalgamated PRIVATE "${SAFETYHOOK_AMALGAMATED_DIR}")
    target_link_libraries(safetyhook-test-amalgamated PRIVATE Zydis GTest::gtest xbyak::xbyak)
    if(WIN32)
        target_compile_definitions(safetyhook-test-amalgamated PRIVATE NOMINMAX=1)
    endif()
    safetyhook_enable_strict_warnings(safetyhook-test-amalgamated PRIVATE)
    add_dependencies(safetyhook-test-amalgamated safetyhook-amalgamate)
    add_test(NAME safetyhook-amalgamated COMMAND $<TARGET_FILE:safetyhook-test-amalgamated>)
endif()
