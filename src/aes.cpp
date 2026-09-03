#include <optional>

#include "aes/dispatch.hpp"
#include "backend.hpp"
#include "platform/platform.hpp"

namespace aes {
namespace {

AesPath detect() noexcept {
    if (platform::cpu_has_aesni()) return AesPath::Hardware_AESNI;
    if (platform::cpu_has_arm_aes()) return AesPath::Hardware_ARM_CE;
    return AesPath::Software;
}

AesPath cached_detect() noexcept {
    static const AesPath p = detect();
    return p;
}

thread_local std::optional<AesPath> t_override;

}  // namespace

AesPath detect_aes_path() noexcept {
    return cached_detect();
}

const char* aes_path_name(AesPath p) noexcept {
    switch (p) {
        case AesPath::Software:
            return "Software (portable)";
        case AesPath::Hardware_AESNI:
            return "Hardware (AES-NI)";
        case AesPath::Hardware_ARM_CE:
            return "Hardware (ARM CE)";
    }
    return "Unknown";
}

AesPath active_aes_path() noexcept {
    return t_override.value_or(cached_detect());
}

void force_aes_path(AesPath p) noexcept {
    t_override = p;
}
void clear_forced_aes_path() noexcept {
    t_override.reset();
}

namespace detail {

struct Backend {
    backend::ExpandKeyFn ek;
    backend::CtrXorFn cx;
};

Backend get_backend() noexcept {
    switch (active_aes_path()) {
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
        case AesPath::Hardware_AESNI:
            return {backend::ni_expand_key, backend::ni_ctr_xor};
#endif
#if defined(__aarch64__) || defined(_M_ARM64)
        case AesPath::Hardware_ARM_CE:
            return {backend::arm_expand_key, backend::arm_ctr_xor};
#endif
        default:
            return {backend::sw_expand_key, backend::sw_ctr_xor};
    }
}

}  // namespace detail
}  // namespace aes
