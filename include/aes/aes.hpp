#pragma once
#include <array>
#include <cstddef>
#include <cstring>
#include <string>
#include <type_traits>
#include <vector>

#include "aes/container.hpp"
#include "aes/dispatch.hpp"
#include "aes/errors.hpp"
#include "aes/key.hpp"

namespace aes {

struct EncryptResult {
    std::array<std::byte, 16> nonce;
    std::vector<std::byte> ciphertext;
};

/// Encrypt with AES-256-CTR. Nonce is generated fresh from CSPRNG.
EncryptResult encrypt(const Key& key, const std::vector<std::byte>& plaintext);

/// Decrypt AES-256-CTR ciphertext.
std::vector<std::byte> decrypt(const Key& key,
    const std::array<std::byte, 16>& nonce, const std::vector<std::byte>& ct);

void encrypt_to_file(const Key& key, const std::vector<std::byte>& pt, const std::string& path);
std::vector<std::byte> decrypt_from_file(const Key& key, const std::string& path);
std::vector<std::byte> load_file(const std::string& path);
void save_file(const std::vector<std::byte>& data, const std::string& path);

// Template API for trivially copyable types.
template <typename T>
std::enable_if_t<std::is_trivially_copyable_v<T>, EncryptResult>
encrypt_value(const Key& key, const T& value) {
    std::vector<std::byte> bytes(sizeof(T));
    std::memcpy(bytes.data(), &value, sizeof(T));
    return encrypt(key, bytes);
}

template <typename T>
std::enable_if_t<std::is_trivially_copyable_v<T>, T>
decrypt_value(const Key& key, const std::array<std::byte, 16>& nonce,
              const std::vector<std::byte>& ct) {
    auto pt = decrypt(key, nonce, ct);
    if (pt.size() != sizeof(T)) throw FormatError("size mismatch");
    T v;
    std::memcpy(&v, pt.data(), sizeof(T));
    return v;
}

template <typename T>
std::enable_if_t<std::is_trivially_copyable_v<T>, EncryptResult>
encrypt_values(const Key& key, const std::vector<T>& vals) {
    std::vector<std::byte> bytes(vals.size() * sizeof(T));
    if (!vals.empty()) std::memcpy(bytes.data(), vals.data(), bytes.size());
    return encrypt(key, bytes);
}

} // namespace aes