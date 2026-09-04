#include <gtest/gtest.h>
#include "aes/aes.hpp"
#include <cstring>
#include <string>

// NIST SP 800-38A F.5.5 — CTR-AES256.Encrypt
namespace {
std::vector<std::byte> hex(const std::string& s) {
    std::vector<std::byte> v;
    for (std::size_t i = 0; i < s.size(); i += 2)
        v.push_back(static_cast<std::byte>(
            std::stoul(s.substr(i, 2), nullptr, 16)));
    return v;
}

void run_kat() {
    auto key = hex("603deb1015ca71be2b73aef0857d7781"
                   "1f352c073b6108d72d9810a30914dff4");
    auto ctr = hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    auto pt  = hex("6bc1bee22e409f96e93d7e117393172a"
                   "ae2d8a571e03ac9c9eb76fac45af8e51"
                   "30c81c46a35ce411e5fbc1191a0a52ef"
                   "f69f2445df4f9b17ad2b417be66c3710");
    auto exp = hex("601ec313775789a5b7a7f504bbf3d228"
                   "f443e3ca4d62b59aca84e990cacaf5c5"
                   "2b0930daa23de94ce87017ba2d84988d"
                   "dfc9c58db67aada613c2dd08457941a6");
    auto k = aes::Key::from_span(key.data(), key.size());
    std::array<std::byte, 16> nonce{};
    std::memcpy(nonce.data(), ctr.data(), 16);
    EXPECT_EQ(aes::decrypt(k, nonce, pt), exp);
}
} // anonymous namespace

class KatTest : public ::testing::Test {
protected:
    void TearDown() override { aes::clear_forced_aes_path(); }
};

TEST_F(KatTest, Software) {
    aes::force_aes_path(aes::AesPath::Software);
    run_kat();
}

TEST_F(KatTest, Hardware) {
    auto p = aes::detect_aes_path();
    if (p == aes::AesPath::Software) GTEST_SKIP() << "no hw aes";
    aes::force_aes_path(p);
    run_kat();
}