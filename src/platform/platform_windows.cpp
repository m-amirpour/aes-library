#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <ntstatus.h>
#include <windows.h>

// WORKAROUND: Fix Windows 11 SDK (10.0.26100.0) bug where SAL annotations
// conflict with strict C++17 conformance inside <bcrypt.h> line 39.
#ifdef _Return_type_success_
#undef _Return_type_success_
#endif
#define _Return_type_success_(expr)

#include <bcrypt.h>
#include <intrin.h>  // __cpuid

#include <string>  // std::string

#include "aes/errors.hpp"
#include "platform.hpp"

namespace aes::platform {

void csprng_fill(void* buf, std::size_t len) {
    if (len == 0) return;
    if (!buf) throw RandomError("null buffer");

    NTSTATUS s = ::BCryptGenRandom(nullptr, static_cast<PUCHAR>(buf), static_cast<ULONG>(len),
                                   BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(s)) throw RandomError("BCryptGenRandom failed");
}

void secure_zero(void* ptr, std::size_t len) noexcept {
    if (!ptr || len == 0) return;
    ::SecureZeroMemory(ptr, len);
}

bool lock_memory(void* ptr, std::size_t len) noexcept {
    if (!ptr || len == 0) return true;
    return ::VirtualLock(ptr, len) != 0;
}

void unlock_memory(void* ptr, std::size_t len) noexcept {
    if (!ptr || len == 0) return;
    ::VirtualUnlock(ptr, len);
}

bool cpu_has_aesni() noexcept {
#if defined(_M_X64) || defined(_M_IX86)
    int info[4] = {};
    __cpuid(info, 1);
    return (info[2] & (1 << 25)) != 0;
#else
    return false;
#endif
}

bool cpu_has_arm_aes() noexcept {
#if defined(_M_ARM64)
    return ::IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE) != 0;
#else
    return false;
#endif
}

void read_file_exact(const std::string& path, void* buf, std::size_t size) {
    HANDLE h = ::CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                             FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) throw IoError("cannot open: " + path);
    LARGE_INTEGER fs;
    if (!::GetFileSizeEx(h, &fs) || static_cast<std::size_t>(fs.QuadPart) != size) {
        ::CloseHandle(h);
        throw IoError("size mismatch: " + path);
    }
    DWORD read = 0;
    if (!::ReadFile(h, buf, static_cast<DWORD>(size), &read, nullptr) || read != size) {
        ::CloseHandle(h);
        throw IoError("read failed: " + path);
    }
    ::CloseHandle(h);
}

void write_file_exact(const std::string& path, const void* buf, std::size_t size) {
    HANDLE h = ::CreateFileA(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                             FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) throw IoError("cannot create: " + path);
    DWORD written = 0;
    if (!::WriteFile(h, buf, static_cast<DWORD>(size), &written, nullptr) || written != size) {
        ::CloseHandle(h);
        throw IoError("write failed: " + path);
    }
    ::FlushFileBuffers(h);
    ::CloseHandle(h);
}

}  // namespace aes::platform
