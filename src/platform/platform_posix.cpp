#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

#include "aes/errors.hpp"
#include "platform.hpp"

#if defined(__linux__)
#include <sys/random.h>
#endif
#if defined(__APPLE__)
#include <Security/SecRandom.h>
#endif
#if defined(__aarch64__) && defined(__linux__)
#include <asm/hwcap.h>
#include <sys/auxv.h>
#endif
#if defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#endif

namespace aes::platform {

void csprng_fill(void* buf, std::size_t len) {
    if (len == 0) return;
    if (!buf) throw RandomError("null buffer");

#if defined(__APPLE__)
    if (SecRandomCopyBytes(kSecRandomDefault, len, buf) != errSecSuccess)
        throw RandomError("SecRandomCopyBytes failed");
#elif defined(__linux__)
    auto* p = static_cast<unsigned char*>(buf);
    std::size_t rem = len;
    while (rem > 0) {
        ssize_t got = getrandom(p, rem, 0);
        if (got < 0) {
            if (errno == EINTR) continue;
            throw RandomError("getrandom failed");
        }
        p += got;
        rem -= static_cast<std::size_t>(got);
    }
#else
    int fd = ::open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) throw RandomError("cannot open /dev/urandom");
    auto* p = static_cast<unsigned char*>(buf);
    std::size_t rem = len;
    while (rem > 0) {
        ssize_t got = ::read(fd, p, rem);
        if (got < 0) {
            if (errno == EINTR) continue;
            ::close(fd);
            throw RandomError("read failed");
        }
        if (got == 0) {
            ::close(fd);
            throw RandomError("EOF");
        }
        p += got;
        rem -= static_cast<std::size_t>(got);
    }
    ::close(fd);
#endif
}

void secure_zero(void* ptr, std::size_t len) noexcept {
    if (!ptr || len == 0) return;
#if defined(__linux__)
    explicit_bzero(ptr, len);
#elif defined(__APPLE__) || defined(__FreeBSD__)
    memset_s(ptr, len, 0, len);
#else
    volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
    while (len--) *p++ = 0;
#endif
}

bool lock_memory(void* ptr, std::size_t len) noexcept {
    if (!ptr || len == 0) return true;
    return ::mlock(ptr, len) == 0;
}

void unlock_memory(void* ptr, std::size_t len) noexcept {
    if (!ptr || len == 0) return;
    ::munlock(ptr, len);
}

bool cpu_has_aesni() noexcept {
#if defined(__x86_64__) || defined(__i386__)
    unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
    if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx)) return false;
    return (ecx & (1u << 25)) != 0;
#else
    return false;
#endif
}

bool cpu_has_arm_aes() noexcept {
#if defined(__aarch64__) && defined(__linux__)
    return (getauxval(AT_HWCAP) & HWCAP_AES) != 0;
#else
    return false;
#endif
}

void read_file_exact(const std::string& path, void* buf, std::size_t size) {
    int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) throw IoError("cannot open: " + path);
    struct stat st{};
    if (::fstat(fd, &st) != 0 || static_cast<std::size_t>(st.st_size) != size) {
        ::close(fd);
        throw IoError("size mismatch: " + path);
    }
    auto* p = static_cast<unsigned char*>(buf);
    std::size_t rem = size;
    while (rem > 0) {
        ssize_t got = ::read(fd, p, rem);
        if (got < 0) {
            if (errno == EINTR) continue;
            ::close(fd);
            throw IoError("read: " + path);
        }
        if (got == 0) {
            ::close(fd);
            throw IoError("EOF: " + path);
        }
        p += got;
        rem -= static_cast<std::size_t>(got);
    }
    ::close(fd);
}

void write_file_exact(const std::string& path, const void* buf, std::size_t size) {
    // 0600 — owner only, since this is used for key files
    int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, S_IRUSR | S_IWUSR);
    if (fd < 0) throw IoError("cannot create: " + path);
    const auto* p = static_cast<const unsigned char*>(buf);
    std::size_t rem = size;
    while (rem > 0) {
        ssize_t w = ::write(fd, p, rem);
        if (w < 0) {
            if (errno == EINTR) continue;
            ::close(fd);
            throw IoError("write: " + path);
        }
        p += w;
        rem -= static_cast<std::size_t>(w);
    }
    ::fsync(fd);
    ::close(fd);
}

}  // namespace aes::platform
