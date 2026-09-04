#include <gtest/gtest.h>
#include "aes/container.hpp"
#include "aes/errors.hpp"
#include <cstdio>

TEST(Container, RoundTrip) {
    aes::Container c;
    for (int i = 0; i < 16; ++i)
        c.header.nonce[static_cast<std::size_t>(i)] = static_cast<std::byte>(i);
    c.ciphertext.resize(50);
    for (std::size_t i = 0; i < 50; ++i)
        c.ciphertext[i] = static_cast<std::byte>(i * 3);
    c.header.ciphertext_length = 50;
    auto s = aes::serialize_container(c);
    auto d = aes::deserialize_container(s);
    EXPECT_EQ(d.header.version, 1);
    EXPECT_EQ(d.header.nonce, c.header.nonce);
    EXPECT_EQ(d.ciphertext, c.ciphertext);
}

TEST(Container, BadMagic) {
    std::vector<std::byte> bad(32, std::byte{0xff});
    EXPECT_THROW(aes::deserialize_container(bad), aes::FormatError);
}

TEST(Container, Short) {
    std::vector<std::byte> tiny(10, std::byte{0});
    EXPECT_THROW(aes::deserialize_container(tiny), aes::FormatError);
}

TEST(Container, BadVersion) {
    aes::Container c;
    auto s = aes::serialize_container(c);
    s[4] = std::byte{99};
    EXPECT_THROW(aes::deserialize_container(s), aes::FormatError);
}

TEST(Container, FileRoundTrip) {
    aes::Container c;
    c.ciphertext = {std::byte{1}, std::byte{2}, std::byte{3}};
    c.header.ciphertext_length = 3;
    const std::string p = "test_ctr_tmp.bin";
    aes::save_container(c, p);
    auto loaded = aes::load_container(p);
    EXPECT_EQ(loaded.ciphertext, c.ciphertext);
    std::remove(p.c_str());
}