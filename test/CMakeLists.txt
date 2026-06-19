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
set_target_properties(safetyhook-test PROPERTIES OUTPUT_NAME test)
target_compile_features(safetyhook-test PRIVATE cxx_std_23)
target_link_libraries(safetyhook-test PRIVATE GTest::gtest safetyhook::safetyhook xbyak::xbyak)
add_test(NAME safetyhook COMMAND $<TARGET_FILE:safetyhook-test>)

if(SAFETYHOOK_AMALGAMATE)
    add_executable(safetyhook-test-amalgamated
        ${SAFETYHOOK_TEST_SOURCES}
        "${PROJECT_SOURCE_DIR}/amalgamated-dist/safetyhook.cpp"
    )
    set_target_properties(safetyhook-test-amalgamated PROPERTIES OUTPUT_NAME test-amalgamated)
    target_compile_features(safetyhook-test-amalgamated PRIVATE cxx_std_23)
    target_include_directories(safetyhook-test-amalgamated PRIVATE "${PROJECT_SOURCE_DIR}/amalgamated-dist")
    target_link_libraries(safetyhook-test-amalgamated PRIVATE Zydis GTest::gtest xbyak::xbyak)
    add_dependencies(safetyhook-test-amalgamated safetyhook-amalgamate)
    add_test(NAME safetyhook-amalgamated COMMAND $<TARGET_FILE:safetyhook-test-amalgamated>)
endif()
