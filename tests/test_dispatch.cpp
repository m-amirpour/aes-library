#include <gtest/gtest.h>
#include "aes/aes.hpp"
#include <cstring>
#include <thread>

namespace {
std::vector<std::byte> pat(std::size_t n) {
    std::vector<std::byte> v(n);
    for (std::size_t i = 0; i < n; ++i)
        v[i] = static_cast<std::byte>((i * 31 + 7) & 0xff);
    return v;
}
}

class DispatchTest : public ::testing::Test {
protected:
    void TearDown() override { aes::clear_forced_aes_path(); }
};

TEST_F(DispatchTest, ValidPath) {
    auto p = aes::detect_aes_path();
    EXPECT_TRUE(p == aes::AesPath::Software ||
                p == aes::AesPath::Hardware_AESNI ||
                p == aes::AesPath::Hardware_ARM_CE);
}

TEST_F(DispatchTest, SoftwareRoundTrip) {
    aes::force_aes_path(aes::AesPath::Software);
    auto k = aes::Key::generate();
    auto pt = pat(200);
    auto enc = aes::encrypt(k, pt);
    EXPECT_EQ(aes::decrypt(k, enc.nonce, enc.ciphertext), pt);
}

TEST_F(DispatchTest, HardwareIfAvailable) {
    auto d = aes::detect_aes_path();
    if (d == aes::AesPath::Software) GTEST_SKIP() << "no hw aes";
    aes::force_aes_path(d);
    auto k = aes::Key::generate();
    auto pt = pat(200);
    auto enc = aes::encrypt(k, pt);
    EXPECT_EQ(aes::decrypt(k, enc.nonce, enc.ciphertext), pt);
}

TEST_F(DispatchTest, Interop) {
    auto d = aes::detect_aes_path();
    if (d == aes::AesPath::Software) GTEST_SKIP() << "no hw aes";
    auto pt = pat(500);
    aes::force_aes_path(aes::AesPath::Software);
    auto ksw = aes::Key::generate();
    std::byte raw[32];
    std::memcpy(raw, ksw.data(), 32);
    aes::force_aes_path(d);
    auto khw = aes::Key::from_span(raw, 32);
    auto enc = aes::encrypt(khw, pt);
    aes::force_aes_path(aes::AesPath::Software);
    auto ksw2 = aes::Key::from_span(raw, 32);
    EXPECT_EQ(aes::decrypt(ksw2, enc.nonce, enc.ciphertext), pt);
}

TEST_F(DispatchTest, ThreadLocal) {
    aes::force_aes_path(aes::AesPath::Software);
    aes::AesPath other = aes::AesPath::Hardware_AESNI;
    std::thread t([&]{ other = aes::active_aes_path(); });
    t.join();
    EXPECT_EQ(other, aes::detect_aes_path());
    EXPECT_EQ(aes::active_aes_path(), aes::AesPath::Software);
}