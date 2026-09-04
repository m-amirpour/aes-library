# aes-library

AES-256-CTR with runtime hardware acceleration. Uses AES-NI on x86-64 or
ARMv8 crypto extensions on AArch64 when available, falls back to a software
implementation otherwise. Same binary works on both — no recompile.

## What's in the box

The library encrypts and decrypts std::vector<std::byte> using AES-256-CTR.
Keys are generated from the OS CSPRNG. Encrypted data is stored in a small
binary container format that includes the nonce and a version header so the
format can evolve later. Keys and ciphertext live in separate files.

There's also a template API if you want to encrypt trivially-copyable structs
directly, and a C ABI shared library with a Python ctypes example.

## Building

You need CMake 3.20+ and a C++17 compiler. That's it.

Linux (Fedora):

    sudo dnf install gcc-c++ cmake git
    mkdir build && cd build
    cmake .. -DCMAKE_BUILD_TYPE=Release
    cmake --build . -j

Linux (Debian/Ubuntu):

    sudo apt install build-essential cmake git

Windows (MSVC):

    mkdir build && cd build
    cmake .. -G "Visual Studio 17 2022" -A x64
    cmake --build . --config Release

GoogleTest is fetched automatically on the first configure via FetchContent,
so you don't need to install it yourself.

If you don't want tests or the C bindings, pass -DAES_BUILD_TESTS=OFF or
-DAES_BUILD_BINDINGS=OFF to cmake.

## Running

The test harness does a full round-trip: generate plaintext, encrypt, save
to disk, load back, decrypt, compare. It prints which code path was used.

    ./aes_harness

Unit tests (25 of them, covering round-trips, NIST vectors, dispatch, etc):

    ctest --output-on-failure

Python demo (needs the shared lib built):

    python3 bindings/python/example.py

## AI tools

I used Claude during development, mostly to sanity-check the AES-NI
intrinsic sequences against Intel's docs and to think through the key
material lifecycle. The code was written and debugged by me. If something
is wrong it's my fault, not the AI's.

## License

Assessment submission for Spara. Not for redistribution.