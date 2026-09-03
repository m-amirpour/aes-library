#pragma once
#include <cstddef>
#include <string>

#include "secure_memory.hpp"

namespace aes {

inline constexpr std::size_t AES256_KEY_SIZE = 32;
inline constexpr std::size_t AES_BLOCK_SIZE = 16;
inline constexpr std::size_t AES256_RK_SIZE = 240;  // 15 round keys * 16 bytes

// Move-only. Key expansion happens in the constructor so the object
// is immutable after creation — safe to share const Key& across threads.
class Key {
   public:
    static Key generate();
    static Key from_bytes(SecureBytes raw);
    static Key from_span(const std::byte* data, std::size_t len);
    static Key load_from_file(const std::string& path);
    void save_to_file(const std::string& path) const;

    const std::byte* data() const noexcept { return raw_.data(); }
    std::size_t size() const noexcept { return raw_.size(); }
    const std::byte* expanded_key() const noexcept { return rk_.data(); }

    Key(Key&&) noexcept = default;
    Key& operator=(Key&&) noexcept = default;
    Key(const Key&) = delete;
    Key& operator=(const Key&) = delete;
    ~Key() = default;

   private:
    explicit Key(SecureBytes raw);
    SecureBytes raw_;
    SecureBytes rk_;
};

}  // namespace aes
