#!/usr/bin/env python3
"""Minimal Python example calling the AES library via ctypes."""

import ctypes
import os
import sys


def load_lib():
    if sys.platform.startswith("linux"):
        name = "libaes_capi.so"
    elif sys.platform == "darwin":
        name = "libaes_capi.dylib"
    else:
        name = "aes_capi.dll"

    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.abspath(os.path.join(here, "..", ".."))

    # Strictly absolute paths to satisfy Python 3.8+ Windows security rules
    candidates = [
        os.path.abspath(os.path.join(root, "build", "Release", name)),
        os.path.abspath(os.path.join(root, "build", "Debug", name)),
        os.path.abspath(os.path.join(root, "build", name)),
        os.path.abspath(os.path.join(here, name)),
    ]

    for c in candidates:
        if os.path.exists(c):
            # On Windows with Python >= 3.8, explicitly authorize the DLL's directory
            if sys.platform == "win32" and hasattr(os, "add_dll_directory"):
                try:
                    os.add_dll_directory(os.path.dirname(c))
                except Exception:
                    pass
            return ctypes.CDLL(c)

    search_paths = "\n".join(f"  - {c}" for c in candidates)
    raise RuntimeError(f"Could not find {name}. Searched in:\n{search_paths}")


def main():
    lib = load_lib()

    lib.aes_active_path_name.restype = ctypes.c_char_p

    lib.aes_key_generate.restype = ctypes.c_void_p
    lib.aes_key_free.argtypes = [ctypes.c_void_p]

    lib.aes_encrypt.restype = ctypes.c_int
    lib.aes_encrypt.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_size_t),
    ]

    lib.aes_decrypt.restype = ctypes.c_int
    lib.aes_decrypt.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_size_t),
    ]

    print("Active path:", lib.aes_active_path_name().decode())

    key = lib.aes_key_generate()
    if not key:
        print("ERROR: aes_key_generate failed")
        return 1

    try:
        msg = b"Hello from Python via C API on Windows!"
        pt = (ctypes.c_uint8 * len(msg))(*msg)
        nonce = (ctypes.c_uint8 * 16)()
        ct = (ctypes.c_uint8 * len(msg))()
        ct_len = ctypes.c_size_t(0)

        ret = lib.aes_encrypt(key, pt, len(msg), nonce, ct, ctypes.byref(ct_len))
        assert ret == 0, "Encryption failed"

        dec = (ctypes.c_uint8 * ct_len.value)()
        dec_len = ctypes.c_size_t(0)

        ret = lib.aes_decrypt(key, nonce, ct, ct_len.value, dec, ctypes.byref(dec_len))
        assert ret == 0, "Decryption failed"

        recovered = bytes(dec[: dec_len.value])
        assert recovered == msg, "Decrypted text mismatch"

        print("Round-trip OK:", recovered.decode())
    finally:
        lib.aes_key_free(key)


if __name__ == "__main__":
    main()
