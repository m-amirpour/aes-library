# Design notes

This is a walkthrough of the decisions I made and why. If you just want to
use the library, the README is enough.

## Overall structure

The library is split into three layers. The public API in include/aes/ is
what callers see: encrypt(), decrypt(), the Key class, file helpers. Below
that sits the dispatch layer which picks a backend at runtime. At the bottom
is a platform abstraction that isolates all the OS-specific stuff (random
number generation, memory locking, CPUID, file I/O) so the rest of the code
doesn't have #ifdef _WIN32 scattered everywhere.

The backend interface is deliberately minimal — just two function pointers
per backend: one to expand the key schedule, one to do the CTR XOR loop.
This means adding a new architecture is just adding one .cpp file and a
case in the dispatch switch. Nothing else needs to change.

## Hardware dispatch

The hard part about "same binary, any CPU" is that you can't just compile
everything with -maes. If you do, the compiler will happily emit AES-NI
instructions in random places, and the binary will SIGILL on older CPUs.

The fix is to scope the intrinsic flags to only the hardware backend files.
In CMake this is done with set_source_files_properties on aes_ni.cpp and
aes_arm.cpp. Every other translation unit compiles without those flags, so
no AES instructions can leak into common code.

At runtime, detect_aes_path() runs CPUID (x86) or checks getauxval (ARM
Linux) once and caches the result in a function-local static. The dispatcher
then calls through function pointers to the right backend. There's no switch
statement in the hot path.

For testing, force_aes_path() lets you override the path per-thread using
thread_local. This way the test suite can exercise both software and
hardware paths on the same machine without threads stepping on each other.

## Nonce strategy

CTR mode is broken if you reuse a (key, nonce) pair. It degrades to a
two-time pad and the attacker can XOR two ciphertexts to get the XOR of
the two plaintexts. So nonce management is critical.

I went with the standard NIST construction: 96 bits of random data from the
OS CSPRNG, followed by a 32-bit big-endian counter starting at zero. The
96-bit random part gives a birthday bound of roughly 2^48 encryptions before
you'd expect a collision, which is plenty. The 32-bit counter allows up to
64 GiB of data per encryption call.

The caller never gets to pick the nonce — encrypt() generates it internally.
This makes the common misuse case (passing a fixed IV) impossible. The
decrypt() function takes a nonce because it obviously needs to match what
encryption used.

If someone tries to encrypt more than 64 GiB in one shot, the library throws
a CryptoError instead of silently wrapping the counter. A production library
would probably split the data across multiple nonces, but that's a streaming
API problem and out of scope here.

## Container format

The on-disk format is dead simple. 32-byte header, then the ciphertext:

Bytes 0-3:   magic "AE5\0" so you can tell it's not a random file
Bytes 4-5:   version number (currently 1, little-endian)
Bytes 6-7:   algorithm ID (0x0001 = AES-256-CTR)
Bytes 8-23:  the 16-byte nonce
Bytes 24-31: ciphertext length as a 64-bit little-endian integer
Bytes 32+:   the actual ciphertext

The explicit length field is there so a future version 2 could tack on an
HMAC tag or something after the ciphertext without breaking old readers.
The version field means readers can reject formats they don't understand
instead of silently producing garbage.

The big thing missing here is authentication. CTR gives you confidentiality
but not integrity — an attacker can flip bits in the ciphertext and the
same bits flip in the plaintext. For real use you'd want AES-GCM or at
least CTR + HMAC. That's the first thing I'd add for a v2 format.

## Key handling

The Key class is move-only. You literally cannot copy it. This prevents the
most common key management mistake: accidentally duplicating key material
into a log line, a container reallocation, or a closure capture.

Key expansion happens in the constructor, not lazily on first use. I know
lazy init sounds appealing, but it creates a data race if two threads share
a const Key& and both try to encrypt at the same time. Eager expansion means
the Key is fully immutable after construction and safe to share across
threads with zero locking.

Key bytes live in a custom SecureAllocator that calls mlock() to keep the
pages out of swap and uses explicit_bzero (or SecureZeroMemory on Windows)
to wipe memory before freeing it. The compiler can't optimize these zeros
away.

Key files are read and written using raw OS system calls (open/read/write
on POSIX, CreateFile on Windows) instead of std::fstream. The reason is
that fstream maintains internal heap buffers, and when the stream is
destroyed those buffers are freed without being zeroed. So your key would
sit in unallocated heap memory waiting to be scraped. Raw syscalls let us
read directly into our locked, zeroed-on-free buffers.

On POSIX, key files are created with mode 0600 so only the owner can read
them.

## Software AES

The fallback backend computes the S-box at compile time using constexpr
GF(2^8) arithmetic (multiplicative inverse via Fermat's little theorem,
then the standard affine transform). The math is correct — it passes the
NIST test vector.

The S-box is stored as a 256-byte lookup table, which means it has
cache-timing side channels. An attacker who shares your CPU cache can
observe which table entries you access and recover key bits. I'm aware of
this and it's a deliberate trade-off. On any CPU made in the last 10+ years,
the hardware path handles the hot loop and is constant-time by construction.
The software path is a correctness fallback for weird or old hardware. If I
were deploying this in an environment without hardware AES, I'd replace it
with a bitsliced implementation, but that's a lot more code and not the
point of this exercise.

## Error handling

All exceptions inherit from aes::Error, which inherits from
std::runtime_error. There are five subclasses: RandomError, KeyError,
FormatError, IoError, and CryptoError. This lets callers catch specific
failures or just catch aes::Error to handle everything the library might
throw, without accidentally swallowing unrelated exceptions from other code.

## What I'd do differently for production

Add AES-GCM or CTR+HMAC for authenticated encryption. The lack of integrity
protection is the biggest gap. I'd also add a streaming API for data larger
than memory, password-based key derivation (Argon2id), and OS keystore
integration (DPAPI on Windows, libsecret on Linux, Keychain on macOS).