#include <gtest/gtest.h>
#include "aes/aes.hpp"
#include <cstring>

TEST(Templates, Int) {
    auto k = aes::Key::generate();
    int v = -12345;
    auto e = aes::encrypt_value(k, v);
    EXPECT_EQ(aes::decrypt_value<int>(k, e.nonce, e.ciphertext), v);
}

TEST(Templates, Struct) {
    struct P { int a; float b; char c[4]; };
    auto k = aes::Key::generate();
    P v{7, 1.5f, {'X','Y','Z',0}};
    auto e = aes::encrypt_value(k, v);
    auto d = aes::decrypt_value<P>(k, e.nonce, e.ciphertext);
    EXPECT_EQ(d.a, v.a);
    EXPECT_FLOAT_EQ(d.b, v.b);
    EXPECT_STREQ(d.c, v.c);
}

TEST(Templates, WrongSize) {
    auto k = aes::Key::generate();
    int v = 42;
    auto e = aes::encrypt_value(k, v);
    EXPECT_THROW((aes::decrypt_value<double>(k, e.nonce, e.ciphertext)),
                 aes::FormatError);
}