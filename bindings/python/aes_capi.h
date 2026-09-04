#ifndef AES_CAPI_H
#define AES_CAPI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
#define AES_EXPORT __declspec(dllexport)
#else
#define AES_EXPORT __attribute__((visibility("default")))
#endif

typedef struct aes_key_s* aes_key_t;

AES_EXPORT const char* aes_active_path_name(void);
AES_EXPORT aes_key_t aes_key_generate(void);
AES_EXPORT void aes_key_free(aes_key_t key);

AES_EXPORT int aes_encrypt(aes_key_t key,
    const uint8_t* pt, size_t pt_len,
    uint8_t* nonce_out, uint8_t* ct_out, size_t* ct_len_out);

AES_EXPORT int aes_decrypt(aes_key_t key,
    const uint8_t* nonce, const uint8_t* ct, size_t ct_len,
    uint8_t* pt_out, size_t* pt_len_out);

#ifdef __cplusplus
}
#endif
#endif