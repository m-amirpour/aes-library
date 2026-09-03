#pragma once
#include <cstdint>

namespace aes {

enum class AesPath : uint8_t {
    Software,
    Hardware_AESNI,
    Hardware_ARM_CE,
};

AesPath detect_aes_path() noexcept;
const char* aes_path_name(AesPath p) noexcept;
AesPath active_aes_path() noexcept;

// Thread-local override for testing. Don't use in production code.
void force_aes_path(AesPath p) noexcept;
void clear_forced_aes_path() noexcept;

}  // namespace aes
