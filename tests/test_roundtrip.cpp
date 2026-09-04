#include <gtest/gtest.h>
#include "aes/aes.hpp"
#include <cstring>

namespace {
std::vector<std::byte> pattern(std::size_t n, unsigned seed = 0x9e3779b9u) {
    std::vector<std::byte> v(n);
    unsigned x = seed;
    for (std::size_t i = 0; i < n; ++i) {
        x = x * 1664525u + 1013904223u;
        v[i] = static_cast<std::byte>(x & 0xff);
    }
    return v;
}
}

TEST(RoundTrip, Empty) {
    auto k = aes::Key::generate();
    std::vector<std::byte> e;
    auto enc = aes::encrypt(k, e);
    auto dec = aes::decrypt(k, enc.nonce, enc.ciphertext);
    EXPECT_TRUE(dec.empty());
}

TEST(RoundTrip, SmallSizes) {
    auto k = aes::Key::generate();
    for (std::size_t n : {1u, 7u, 15u, 16u, 17u, 31u, 32u, 33u, 63u, 64u, 65u}) {
        auto pt = pattern(n);
        auto enc = aes::encrypt(k, pt);
        auto dec = aes::decrypt(k, enc.nonce, enc.ciphertext);
        EXPECT_EQ(dec, pt) << "size " << n;
    }
}

TEST(RoundTrip, Large) {
    auto k = aes::Key::generate();
    auto pt = pattern(1 << 20);
    auto enc = aes::encrypt(k, pt);
    auto dec = aes::decrypt(k, enc.nonce, enc.ciphertext);
    EXPECT_EQ(dec, pt);
}

TEST(RoundTrip, FreshNonces) {
    auto k = aes::Key::generate();
    auto pt = pattern(100);
    auto e1 = aes::encrypt(k, pt);
    auto e2 = aes::encrypt(k, pt);
    EXPECT_NE(e1.nonce, e2.nonce);
    EXPECT_NE(e1.ciphertext, e2.ciphertext);
}

TEST(RoundTrip, WrongKey) {
    auto k1 = aes::Key::generate();
    auto k2 = aes::Key::generate();
    auto pt = pattern(48);
    auto enc = aes::encrypt(k1, pt);
    auto dec = aes::decrypt(k2, enc.nonce, enc.ciphertext);
    EXPECT_NE(dec, pt);
}