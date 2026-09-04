#include "aes/aes.hpp"
#include "backend.hpp"
#include "platform/platform.hpp"
#include <cstring>
#include <fstream>

namespace aes {

namespace detail {
struct Backend { void(*ek)(const std::byte*,std::byte*); void(*cx)(const std::byte*,const std::byte*,const std::byte*,std::byte*,std::size_t); };
Backend get_backend() noexcept;
}

namespace {
// 32-bit counter means max 2^32 blocks. Stop before wrap.
constexpr uint64_t MAX_BYTES = (uint64_t{1}<<32)*16 - 16;
}

EncryptResult encrypt(const Key& key, const std::vector<std::byte>& pt) {
    if (pt.size() > MAX_BYTES) throw CryptoError("plaintext too large");
    EncryptResult r;
    std::byte rnd[12];
    platform::csprng_fill(rnd, 12);
    std::memcpy(r.nonce.data(), rnd, 12);
    r.nonce[12] = r.nonce[13] = r.nonce[14] = r.nonce[15] = std::byte{0};
    secure_zero(rnd, 12);
    r.ciphertext.resize(pt.size());
    if (!pt.empty())
        detail::get_backend().cx(key.expanded_key(), r.nonce.data(),
                                  pt.data(), r.ciphertext.data(), pt.size());
    return r;
}

std::vector<std::byte> decrypt(const Key& key,
    const std::array<std::byte,16>& nonce, const std::vector<std::byte>& ct) {
    if (ct.size() > MAX_BYTES) throw CryptoError("ciphertext too large");
    std::vector<std::byte> pt(ct.size());
    if (!ct.empty())
        detail::get_backend().cx(key.expanded_key(), nonce.data(),
                                  ct.data(), pt.data(), ct.size());
    return pt;
}

void encrypt_to_file(const Key& key, const std::vector<std::byte>& pt, const std::string& path) {
    auto r = encrypt(key, pt);
    Container c;
    c.header.ciphertext_length = r.ciphertext.size();
    c.header.nonce = r.nonce;
    c.ciphertext = std::move(r.ciphertext);
    save_container(c, path);
}

std::vector<std::byte> decrypt_from_file(const Key& key, const std::string& path) {
    auto c = load_container(path);
    return decrypt(key, c.header.nonce, c.ciphertext);
}

std::vector<std::byte> load_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary|std::ios::ate);
    if (!f) throw IoError("cannot open: " + path);
    auto sz = f.tellg(); f.seekg(0);
    std::vector<std::byte> d(static_cast<std::size_t>(sz));
    f.read(reinterpret_cast<char*>(d.data()), sz);
    return d;
}

void save_file(const std::vector<std::byte>& d, const std::string& path) {
    std::ofstream f(path, std::ios::binary|std::ios::trunc);
    if (!f) throw IoError("cannot write: " + path);
    f.write(reinterpret_cast<const char*>(d.data()), static_cast<std::streamsize>(d.size()));
}

} // namespace aes