set(SAFETYHOOK_TEST_SOURCES
    allocator.cpp
    inline_hook.cpp
    inline_hook.x86_64.cpp
    main.cpp
    mid_hook.cpp
    vmt_hook.cpp
)

add_executable(safetyhook-test ${SAFETYHOOK_TEST_SOURCES})
set_target_properties(safetyhook-test PROPERTIES OUTPUT_NAME test)
target_compile_features(safetyhook-test PRIVATE cxx_std_23)
target_compile_definitions(safetyhook-test PRIVATE BOOST_UT_DISABLE_MODULE)
target_link_libraries(safetyhook-test PRIVATE Boost::ut safetyhook::safetyhook xbyak::xbyak)
add_test(NAME safetyhook COMMAND $<TARGET_FILE:safetyhook-test>)

if(SAFETYHOOK_AMALGAMATE)
    add_executable(safetyhook-test-amalgamated
        ${SAFETYHOOK_TEST_SOURCES}
        "${PROJECT_SOURCE_DIR}/amalgamated-dist/safetyhook.cpp"
    )
    set_target_properties(safetyhook-test-amalgamated PROPERTIES OUTPUT_NAME test-amalgamated)
    target_compile_features(safetyhook-test-amalgamated PRIVATE cxx_std_23)
    target_compile_definitions(safetyhook-test-amalgamated PRIVATE BOOST_UT_DISABLE_MODULE)
    target_include_directories(safetyhook-test-amalgamated PRIVATE "${PROJECT_SOURCE_DIR}/amalgamated-dist")
    target_link_libraries(safetyhook-test-amalgamated PRIVATE Zydis Boost::ut xbyak::xbyak)
    add_dependencies(safetyhook-test-amalgamated Amalgamate)
    add_test(NAME safetyhook-amalgamated COMMAND $<TARGET_FILE:safetyhook-test-amalgamated>)
endif()
