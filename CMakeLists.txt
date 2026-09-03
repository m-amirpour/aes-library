cmake_minimum_required(VERSION 3.20)
project(aes_library VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(AES_BUILD_TESTS "Build unit tests" ON)
option(AES_BUILD_BINDINGS "Build C API shared library" ON)

include(cmake/CompilerWarnings.cmake)

if(AES_BUILD_TESTS)
    include(FetchContent)
    FetchContent_Declare(googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.14.0)
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    enable_testing()
endif()

add_subdirectory(src)

add_executable(aes_harness main.cpp)
target_link_libraries(aes_harness PRIVATE aes_lib)
aes_set_warnings(aes_harness)

if(AES_BUILD_TESTS)
    add_subdirectory(tests)
endif()

if(AES_BUILD_BINDINGS)
    add_library(aes_capi SHARED bindings/python/aes_capi.cpp)
    target_link_libraries(aes_capi PRIVATE aes_lib)
    target_include_directories(aes_capi PRIVATE ${PROJECT_SOURCE_DIR}/bindings/python)
    if(WIN32)
        target_include_directories(aes_capi PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
    endif()
endif()
