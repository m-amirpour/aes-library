#include "aes/container.hpp"
#include "aes/errors.hpp"
#include <cstring>
#include <fstream>

namespace aes {
namespace {
constexpr std::size_t HDR = 32;
constexpr uint16_t VER = 1;
constexpr std::array<std::byte,4> MAGIC = {std::byte{0x41},std::byte{0x45},std::byte{0x35},std::byte{0x00}};

void w16(std::byte* p, uint16_t v) { p[0]=std::byte(v&0xff); p[1]=std::byte((v>>8)&0xff); }
void w64(std::byte* p, uint64_t v) { for(int i=0;i<8;++i) p[i]=std::byte((v>>(8*i))&0xff); }
uint16_t r16(const std::byte* p) {
    return uint16_t(uint16_t(std::to_integer<uint8_t>(p[0])) | (uint16_t(std::to_integer<uint8_t>(p[1]))<<8));
}
uint64_t r64(const std::byte* p) {
    uint64_t v=0; for(int i=0;i<8;++i) v|=uint64_t(std::to_integer<uint8_t>(p[i]))<<(8*i); return v;
}
}

std::vector<std::byte> serialize_container(const Container& c) {
    std::vector<std::byte> o(HDR + c.ciphertext.size());
    std::memcpy(o.data(), MAGIC.data(), 4);
    w16(o.data()+4, c.header.version);
    w16(o.data()+6, static_cast<uint16_t>(c.header.algorithm));
    std::memcpy(o.data()+8, c.header.nonce.data(), 16);
    w64(o.data()+24, c.header.ciphertext_length);
    if (!c.ciphertext.empty())
        std::memcpy(o.data()+HDR, c.ciphertext.data(), c.ciphertext.size());
    return o;
}

Container deserialize_container(const std::vector<std::byte>& d) {
    if (d.size() < HDR) throw FormatError("too small");
    if (std::memcmp(d.data(), MAGIC.data(), 4) != 0) throw FormatError("bad magic");
    Container c;
    c.header.version = r16(d.data()+4);
    if (c.header.version != VER) throw FormatError("unsupported version");
    c.header.algorithm = static_cast<AlgorithmId>(r16(d.data()+6));
    if (c.header.algorithm != AlgorithmId::AES_256_CTR) throw FormatError("unsupported algorithm");
    std::memcpy(c.header.nonce.data(), d.data()+8, 16);
    c.header.ciphertext_length = r64(d.data()+24);
    if (c.header.ciphertext_length > d.size() - HDR) throw FormatError("truncated");
    auto n = static_cast<std::size_t>(c.header.ciphertext_length);
    c.ciphertext.resize(n);
    if (n > 0) std::memcpy(c.ciphertext.data(), d.data()+HDR, n);
    return c;
}

void save_container(const Container& c, const std::string& path) {
    auto b = serialize_container(c);
    std::ofstream f(path, std::ios::binary|std::ios::trunc);
    if (!f) throw IoError("cannot write: " + path);
    f.write(reinterpret_cast<const char*>(b.data()), static_cast<std::streamsize>(b.size()));
}

Container load_container(const std::string& path) {
    std::ifstream f(path, std::ios::binary|std::ios::ate);
    if (!f) throw IoError("cannot open: " + path);
    auto sz = f.tellg(); f.seekg(0);
    std::vector<std::byte> d(static_cast<std::size_t>(sz));
    f.read(reinterpret_cast<char*>(d.data()), sz);
    return deserialize_container(d);
}
} // namespace aes