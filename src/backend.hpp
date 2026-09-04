#pragma once
#include <cstddef>

namespace aes::backend {

using ExpandKeyFn = void (*)(const std::byte* key, std::byte* rk_out);
using CtrXorFn = void (*)(const std::byte* rk, const std::byte* ctr,
                           const std::byte* in, std::byte* out, std::size_t len);

extern const ExpandKeyFn sw_expand_key;
extern const CtrXorFn    sw_ctr_xor;

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
extern const ExpandKeyFn ni_expand_key;
extern const CtrXorFn    ni_ctr_xor;
#endif

#if defined(__aarch64__) || defined(_M_ARM64)
extern const ExpandKeyFn arm_expand_key;
extern const CtrXorFn    arm_ctr_xor;
#endif

} // namespace aes::backend

// Shared struct used by dispatch.cpp, aes.cpp, and key.cpp.
// Defined here so all three files see the exact same type.
namespace aes::detail {

struct Backend {
    backend::ExpandKeyFn ek;
    backend::CtrXorFn    cx;
};

Backend get_backend() noexcept;

} // namespace aes::detail