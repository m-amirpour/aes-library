#include "aes_capi.h"
#include "aes/aes.hpp"
#include <cstring>

namespace {
aes::Key* to_key(aes_key_t k) { return reinterpret_cast<aes::Key*>(k); }
}

extern "C" {

const char* aes_active_path_name(void) {
    return aes::aes_path_name(aes::active_aes_path());
}

aes_key_t aes_key_generate(void) {
    try { return reinterpret_cast<aes_key_t>(new aes::Key(aes::Key::generate())); }
    catch (...) { return nullptr; }
}

void aes_key_free(aes_key_t key) { delete to_key(key); }

int aes_encrypt(aes_key_t key, const uint8_t* pt, size_t pt_len,
                uint8_t* nonce_out, uint8_t* ct_out, size_t* ct_len_out) {
    if (!key || !nonce_out || !ct_len_out) return -1;
    if (pt_len > 0 && (!pt || !ct_out)) return -1;
    try {
        std::vector<std::byte> ptv(pt_len);
        if (pt_len > 0) std::memcpy(ptv.data(), pt, pt_len);
        auto r = aes::encrypt(*to_key(key), ptv);
        std::memcpy(nonce_out, r.nonce.data(), 16);
        if (!r.ciphertext.empty())
            std::memcpy(ct_out, r.ciphertext.data(), r.ciphertext.size());
        *ct_len_out = r.ciphertext.size();
        return 0;
    } catch (...) { return -1; }
}

int aes_decrypt(aes_key_t key, const uint8_t* nonce,
                const uint8_t* ct, size_t ct_len,
                uint8_t* pt_out, size_t* pt_len_out) {
    if (!key || !nonce || !pt_len_out) return -1;
    if (ct_len > 0 && (!ct || !pt_out)) return -1;
    try {
        std::array<std::byte, 16> n{};
        std::memcpy(n.data(), nonce, 16);
        std::vector<std::byte> ctv(ct_len);
        if (ct_len > 0) std::memcpy(ctv.data(), ct, ct_len);
        auto pt = aes::decrypt(*to_key(key), n, ctv);
        if (!pt.empty()) std::memcpy(pt_out, pt.data(), pt.size());
        *pt_len_out = pt.size();
        return 0;
    } catch (...) { return -1; }
}

} // extern "C"