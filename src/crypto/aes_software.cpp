// Portable AES-256-CTR. S-box is computed at compile time via constexpr
// GF(2^8) math rather than hardcoded — easier to verify correctness.
//
// Note: table-based S-box has cache-timing side channels. This is fine
// as a fallback since the hardware path handles the hot path on any
// modern CPU. A production library would use bitslicing here.

#include "backend.hpp"
#include "aes/secure_memory.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>

namespace aes::backend {
namespace {

constexpr uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t r = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) r ^= a;
        uint8_t hi = a & 0x80;
        a = static_cast<uint8_t>(a << 1);
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return r;
}

constexpr uint8_t gf_inv(uint8_t x) {
    if (x == 0) return 0;
    uint8_t a2 = gf_mul(x, x);
    uint8_t a3 = gf_mul(a2, x);
    uint8_t a6 = gf_mul(a3, a3);
    uint8_t a12 = gf_mul(a6, a6);
    uint8_t a15 = gf_mul(a12, a3);
    uint8_t a30 = gf_mul(a15, a15);
    uint8_t a60 = gf_mul(a30, a30);
    uint8_t a63 = gf_mul(a60, a3);
    uint8_t a126 = gf_mul(a63, a63);
    uint8_t a252 = gf_mul(a126, a126);
    return gf_mul(a252, a2); // a^254
}

constexpr uint8_t sbox_val(uint8_t x) {
    uint8_t s = gf_inv(x);
    auto rotl = [](uint8_t v, int n) constexpr {
        return static_cast<uint8_t>((v << n) | (v >> (8 - n)));
    };
    return static_cast<uint8_t>(s ^ rotl(s,1) ^ rotl(s,2) ^ rotl(s,3) ^ rotl(s,4) ^ 0x63);
}

constexpr std::array<uint8_t, 256> make_sbox() {
    std::array<uint8_t, 256> t{};
    for (int i = 0; i < 256; ++i)
        t[static_cast<std::size_t>(i)] = sbox_val(static_cast<uint8_t>(i));
    return t;
}

constexpr auto SBOX = make_sbox();
constexpr uint8_t RCON[10] = {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

inline uint8_t u8(std::byte b) { return std::to_integer<uint8_t>(b); }

inline uint32_t load_be(const std::byte* p) {
    return (uint32_t(u8(p[0]))<<24) | (uint32_t(u8(p[1]))<<16) |
           (uint32_t(u8(p[2]))<<8)  | uint32_t(u8(p[3]));
}

inline void store_be(std::byte* p, uint32_t w) {
    p[0] = std::byte((w>>24)&0xff); p[1] = std::byte((w>>16)&0xff);
    p[2] = std::byte((w>>8)&0xff);  p[3] = std::byte(w&0xff);
}

inline uint32_t sub_word(uint32_t w) {
    return (uint32_t(SBOX[(w>>24)&0xff])<<24) | (uint32_t(SBOX[(w>>16)&0xff])<<16) |
           (uint32_t(SBOX[(w>>8)&0xff])<<8)   | uint32_t(SBOX[w&0xff]);
}

inline uint32_t rot_word(uint32_t w) { return (w<<8)|(w>>24); }

inline uint8_t xtime(uint8_t x) {
    return static_cast<uint8_t>((x<<1) ^ (((x>>7)&1)*0x1b));
}

void expand_key(const std::byte* key, std::byte* rk) {
    uint32_t W[60];
    for (int i = 0; i < 8; ++i) W[i] = load_be(key + 4*i);
    for (int i = 8; i < 60; ++i) {
        uint32_t t = W[i-1];
        if (i % 8 == 0)      t = sub_word(rot_word(t)) ^ (uint32_t(RCON[(i/8)-1]) << 24);
        else if (i % 8 == 4) t = sub_word(t);
        W[i] = W[i-8] ^ t;
    }
    for (int i = 0; i < 60; ++i) store_be(rk + 4*i, W[i]);
    secure_zero(W, sizeof(W));
}

void encrypt_block(const std::byte* rk, std::byte* block) {
    uint8_t s[16];
    for (int i = 0; i < 16; ++i) s[i] = u8(block[i]);
    for (int i = 0; i < 16; ++i) s[i] ^= u8(rk[i]);

    for (int round = 1; round <= 14; ++round) {
        for (int i = 0; i < 16; ++i) s[i] = SBOX[s[i]];

        // ShiftRows
        uint8_t t = s[1]; s[1]=s[5]; s[5]=s[9]; s[9]=s[13]; s[13]=t;
        std::swap(s[2], s[10]); std::swap(s[6], s[14]);
        t = s[15]; s[15]=s[11]; s[11]=s[7]; s[7]=s[3]; s[3]=t;

        // MixColumns (skip last round)
        if (round < 14) {
            for (int c = 0; c < 4; ++c) {
                int b = c*4;
                uint8_t a0=s[b], a1=s[b+1], a2=s[b+2], a3=s[b+3];
                uint8_t tt = static_cast<uint8_t>(a0^a1^a2^a3);
                s[b]   ^= static_cast<uint8_t>(tt ^ xtime(static_cast<uint8_t>(a0^a1)));
                s[b+1] ^= static_cast<uint8_t>(tt ^ xtime(static_cast<uint8_t>(a1^a2)));
                s[b+2] ^= static_cast<uint8_t>(tt ^ xtime(static_cast<uint8_t>(a2^a3)));
                s[b+3] ^= static_cast<uint8_t>(tt ^ xtime(static_cast<uint8_t>(a3^a0)));
            }
        }
        for (int i = 0; i < 16; ++i) s[i] ^= u8(rk[16*round + i]);
    }
    for (int i = 0; i < 16; ++i) block[i] = std::byte(s[i]);
    secure_zero(s, sizeof(s));
}

void ctr_xor(const std::byte* rk, const std::byte* ctr_in,
             const std::byte* in, std::byte* out, std::size_t len) {
    std::byte ctr[16];
    std::memcpy(ctr, ctr_in, 16);
    std::byte ks[16];
    std::size_t off = 0;

    while (off < len) {
        std::memcpy(ks, ctr, 16);
        encrypt_block(rk, ks);
        std::size_t bl = std::min<std::size_t>(16, len - off);
        for (std::size_t i = 0; i < bl; ++i) out[off+i] = in[off+i] ^ ks[i];
        off += bl;
        // Increment last 4 bytes (big-endian counter)
        for (int i = 15; i >= 12; --i) {
            uint8_t v = static_cast<uint8_t>(u8(ctr[i]) + 1);
            ctr[i] = std::byte(v);
            if (v != 0) break;
        }
    }
    secure_zero(ks, 16);
    secure_zero(ctr, 16);
}

} // namespace

const ExpandKeyFn sw_expand_key = &expand_key;
const CtrXorFn    sw_ctr_xor    = &ctr_xor;

} // namespace aes::backend