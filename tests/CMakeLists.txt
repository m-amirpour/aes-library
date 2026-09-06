add_executable(aes_tests
    test_roundtrip.cpp
    test_dispatch.cpp
    test_kat.cpp
    test_container.cpp
    test_key.cpp
    test_templates.cpp
)

target_link_libraries(aes_tests PRIVATE aes_lib gtest gtest_main)

# Explicitly add include paths so both local and CI runners find the headers
target_include_directories(aes_tests PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${googletest_SOURCE_DIR}/googletest/include
)

include(GoogleTest)
gtest_discover_tests(aes_tests)

aes_set_warnings(aes_tests)
