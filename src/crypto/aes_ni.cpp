#include "backend.hpp"
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)

#include "aes/secure_memory.hpp"
#include <cstdint>
#include <cstring>
#include <wmmintrin.h>
#include <emmintrin.h>

namespace aes::backend {
namespace {

inline __m128i kh1(__m128i k, __m128i a) {
    __m128i t = _mm_shuffle_epi32(a, 0xff);
    k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
    k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
    k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
    return _mm_xor_si128(k, t);
}

inline __m128i kh2(__m128i k, __m128i p) {
    __m128i a = _mm_aeskeygenassist_si128(p, 0x00);
    __m128i t = _mm_shuffle_epi32(a, 0xaa);
    k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
    k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
    k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
    return _mm_xor_si128(k, t);
}

void expand_key(const std::byte* key, std::byte* rk) {
    __m128i* r = reinterpret_cast<__m128i*>(rk);
    r[0] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key));
    r[1] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key+16));
    r[2]  = kh1(r[0],  _mm_aeskeygenassist_si128(r[1], 0x01));
    r[3]  = kh2(r[1],  r[2]);
    r[4]  = kh1(r[2],  _mm_aeskeygenassist_si128(r[3], 0x02));
    r[5]  = kh2(r[3],  r[4]);
    r[6]  = kh1(r[4],  _mm_aeskeygenassist_si128(r[5], 0x04));
    r[7]  = kh2(r[5],  r[6]);
    r[8]  = kh1(r[6],  _mm_aeskeygenassist_si128(r[7], 0x08));
    r[9]  = kh2(r[7],  r[8]);
    r[10] = kh1(r[8],  _mm_aeskeygenassist_si128(r[9], 0x10));
    r[11] = kh2(r[9],  r[10]);
    r[12] = kh1(r[10], _mm_aeskeygenassist_si128(r[11], 0x20));
    r[13] = kh2(r[11], r[12]);
    r[14] = kh1(r[12], _mm_aeskeygenassist_si128(r[13], 0x40));
}

inline __m128i enc1(__m128i b, const __m128i* rk) {
    b = _mm_xor_si128(b, rk[0]);
    for (int r = 1; r < 14; ++r) b = _mm_aesenc_si128(b, rk[r]);
    return _mm_aesenclast_si128(b, rk[14]);
}

void ctr_xor(const std::byte* rk_ptr, const std::byte* ctr_in,
             const std::byte* in, std::byte* out, std::size_t len) {
    const __m128i* rk = reinterpret_cast<const __m128i*>(rk_ptr);
    std::byte ctr[16];
    std::memcpy(ctr, ctr_in, 16);

    auto rc = [&]() -> uint32_t {
        return (uint32_t(std::to_integer<uint8_t>(ctr[12]))<<24) |
               (uint32_t(std::to_integer<uint8_t>(ctr[13]))<<16) |
               (uint32_t(std::to_integer<uint8_t>(ctr[14]))<<8)  |
               uint32_t(std::to_integer<uint8_t>(ctr[15]));
    };
    auto wc = [&](uint32_t v) {
        ctr[12]=std::byte((v>>24)&0xff); ctr[13]=std::byte((v>>16)&0xff);
        ctr[14]=std::byte((v>>8)&0xff);  ctr[15]=std::byte(v&0xff);
    };

    uint32_t cv = rc();
    std::size_t off = 0;

    // 4-way pipelined bulk
    while (len - off >= 64) {
        wc(cv);   __m128i b0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(ctr));
        wc(cv+1); __m128i b1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(ctr));
        wc(cv+2); __m128i b2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(ctr));
        wc(cv+3); __m128i b3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(ctr));
        b0=_mm_xor_si128(b0,rk[0]); b1=_mm_xor_si128(b1,rk[0]);
        b2=_mm_xor_si128(b2,rk[0]); b3=_mm_xor_si128(b3,rk[0]);
        for (int r=1;r<14;++r) {
            b0=_mm_aesenc_si128(b0,rk[r]); b1=_mm_aesenc_si128(b1,rk[r]);
            b2=_mm_aesenc_si128(b2,rk[r]); b3=_mm_aesenc_si128(b3,rk[r]);
        }
        b0=_mm_aesenclast_si128(b0,rk[14]); b1=_mm_aesenclast_si128(b1,rk[14]);
        b2=_mm_aesenclast_si128(b2,rk[14]); b3=_mm_aesenclast_si128(b3,rk[14]);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out+off),
            _mm_xor_si128(b0,_mm_loadu_si128(reinterpret_cast<const __m128i*>(in+off))));
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out+off+16),
            _mm_xor_si128(b1,_mm_loadu_si128(reinterpret_cast<const __m128i*>(in+off+16))));
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out+off+32),
            _mm_xor_si128(b2,_mm_loadu_si128(reinterpret_cast<const __m128i*>(in+off+32))));
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out+off+48),
            _mm_xor_si128(b3,_mm_loadu_si128(reinterpret_cast<const __m128i*>(in+off+48))));
        cv += 4; off += 64;
    }

    while (off < len) {
        wc(cv);
        __m128i b = enc1(_mm_loadu_si128(reinterpret_cast<const __m128i*>(ctr)), rk);
        std::size_t bl = std::min<std::size_t>(16, len-off);
        if (bl == 16) {
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out+off),
                _mm_xor_si128(b,_mm_loadu_si128(reinterpret_cast<const __m128i*>(in+off))));
        } else {
            std::byte ks[16];
            _mm_storeu_si128(reinterpret_cast<__m128i*>(ks), b);
            for (std::size_t i = 0; i < bl; ++i) out[off+i] = in[off+i] ^ ks[i];
            secure_zero(ks, 16);
        }
        ++cv; off += bl;
    }
    secure_zero(ctr, 16);
}

} // namespace

const ExpandKeyFn ni_expand_key = &expand_key;
const CtrXorFn    ni_ctr_xor    = &ctr_xor;

} // namespace aes::backend
#endif