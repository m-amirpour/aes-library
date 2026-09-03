#include "aes/key.hpp"

#include <cstring>

#include "aes/errors.hpp"
#include "backend.hpp"
#include "platform/platform.hpp"

namespace aes {

namespace detail {
struct Backend {
    void (*ek)(const std::byte*, std::byte*);
    void (*cx)(const std::byte*, const std::byte*, const std::byte*, std::byte*, std::size_t);
};
Backend get_backend() noexcept;
}  // namespace detail

Key::Key(SecureBytes raw) : raw_(std::move(raw)), rk_(AES256_RK_SIZE) {
    if (raw_.size() != AES256_KEY_SIZE) throw KeyError("key must be 32 bytes");
    detail::get_backend().ek(raw_.data(), rk_.data());
}

Key Key::generate() {
    SecureBytes raw(AES256_KEY_SIZE);
    platform::csprng_fill(raw.data(), raw.size());
    return Key(std::move(raw));
}

Key Key::from_bytes(SecureBytes raw) {
    return Key(std::move(raw));
}

Key Key::from_span(const std::byte* d, std::size_t l) {
    if (l != AES256_KEY_SIZE) throw KeyError("key must be 32 bytes");
    SecureBytes raw(l);
    std::memcpy(raw.data(), d, l);
    return Key(std::move(raw));
}

Key Key::load_from_file(const std::string& path) {
    SecureBytes raw(AES256_KEY_SIZE);
    platform::read_file_exact(path, raw.data(), raw.size());
    return Key(std::move(raw));
}

void Key::save_to_file(const std::string& path) const {
    platform::write_file_exact(path, raw_.data(), raw_.size());
}

}  // namespace aes
