#include <gtest/gtest.h>
#include "aes/key.hpp"
#include "aes/errors.hpp"
#include <cstdio>
#include <cstring>

TEST(Key, Size) {
    auto k = aes::Key::generate();
    EXPECT_EQ(k.size(), aes::AES256_KEY_SIZE);
}

TEST(Key, Unique) {
    auto a = aes::Key::generate();
    auto b = aes::Key::generate();
    EXPECT_NE(std::memcmp(a.data(), b.data(), 32), 0);
}

TEST(Key, BadSize) {
    std::byte raw[16] = {};
    EXPECT_THROW(aes::Key::from_span(raw, 16), aes::KeyError);
}

TEST(Key, FileRoundTrip) {
    auto k = aes::Key::generate();
    const std::string p = "test_key_tmp.bin";
    k.save_to_file(p);
    auto loaded = aes::Key::load_from_file(p);
    EXPECT_EQ(std::memcmp(loaded.data(), k.data(), 32), 0);
    std::remove(p.c_str());
}

TEST(Key, MissingFile) {
    EXPECT_THROW(aes::Key::load_from_file("nope.bin"), aes::IoError);
}