#!/usr/bin/env python3
"""Minimal Python example calling the AES library via ctypes."""
import ctypes, os, sys

def load_lib():
    name = "libaes_capi.so" if sys.platform.startswith("linux") else \
        "libaes_capi.dylib" if sys.platform == "darwin" else "aes_capi.dll"
    here = os.path.dirname(os.path.abspath(__file__))
    for c in [name, os.path.join(here, "..", "..", "build", name)]:
        if os.path.exists(c):
            return ctypes.CDLL(c)
    raise RuntimeError(f"Could not find {name}")

def main():
    lib = load_lib()
    lib.aes_active_path_name.restype = ctypes.c_char_p
    lib.aes_key_generate.restype = ctypes.c_void_p
    lib.aes_key_free.argtypes = [ctypes.c_void_p]
    lib.aes_encrypt.restype = ctypes.c_int
    lib.aes_encrypt.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8),
                                ctypes.c_size_t, ctypes.POINTER(ctypes.c_uint8),
                                ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_size_t)]
    lib.aes_decrypt.restype = ctypes.c_int
    lib.aes_decrypt.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8),
                                ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
                                ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_size_t)]

    print("Active path:", lib.aes_active_path_name().decode())
    key = lib.aes_key_generate()
    try:
        msg = b"Hello from Python via C API!"
        pt = (ctypes.c_uint8 * len(msg))(*msg)
        nonce = (ctypes.c_uint8 * 16)()
        ct = (ctypes.c_uint8 * len(msg))()
        ct_len = ctypes.c_size_t(0)
        assert lib.aes_encrypt(key, pt, len(msg), nonce, ct, ctypes.byref(ct_len)) == 0
        dec = (ctypes.c_uint8 * ct_len.value)()
        dec_len = ctypes.c_size_t(0)
        assert lib.aes_decrypt(key, nonce, ct, ct_len.value, dec, ctypes.byref(dec_len)) == 0
        assert bytes(dec[:dec_len.value]) == msg
        print("Round-trip OK:", bytes(dec[:dec_len.value]).decode())
    finally:
        lib.aes_key_free(key)

if __name__ == "__main__":
    main()