# Detect Architectures
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64")
    set(AES_ARCH_X86 TRUE)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|ARM64|arm64")
    set(AES_ARCH_ARM64 TRUE)
endif()

if(WIN32)
    set(PLATFORM_SRC platform/platform_windows.cpp)
else()
    set(PLATFORM_SRC platform/platform_posix.cpp)
endif()

set(AES_SOURCES
    aes.cpp
    key.cpp
    container.cpp
    dispatch.cpp
    secure_memory.cpp
    crypto/aes_software.cpp
    ${PLATFORM_SRC}
)

if(AES_ARCH_X86)
    list(APPEND AES_SOURCES crypto/aes_ni.cpp)
endif()

if(AES_ARCH_ARM64)
    list(APPEND AES_SOURCES crypto/aes_arm.cpp)
endif()

add_library(aes_lib STATIC ${AES_SOURCES})

target_include_directories(aes_lib
    PUBLIC ${PROJECT_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
)

# Only the hardware backend files get intrinsic flags.
# This prevents AES_NI instructions from leaking into common code.
if(AES_ARCH_X86 AND NOT MSVC)
    set_source_files_properties(crypto/aes_ni.cpp
        PROPERTIES COMPILE_FLAGS "-maes -msse4.1")
endif()
if(AES_ARCH_ARM64 AND NOT MSVC)
    set_source_files_properties(crypto/aes_arm.cpp
        PROPERTIES COMPILE_FLAGS "-march=armv8-a+crypto")
endif()

if(WIN32)
    target_link_libraries(aes_lib PRIVATE bcrypt)
elseif(APPLE)
    target_link_libraries(aes_lib PRIVATE "-framework Security")
endif()

aes_set_warnings(aes_lib)
