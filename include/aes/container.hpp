#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace aes {

// On-disk format v1 (32-byte header, little-endian):
//   [0..4)   Magic "AE5\0"
//   [4..6)   Version (u16)
//   [6..8)   Algorithm (u16) — 0x0001 = AES-256-CTR
//   [8..24)  Nonce (16 bytes)
//   [24..32) Ciphertext length (u64)
//   [32..]   Ciphertext

enum class AlgorithmId : uint16_t { AES_256_CTR = 0x0001 };

struct ContainerHeader {
    uint16_t version = 1;
    AlgorithmId algorithm = AlgorithmId::AES_256_CTR;
    std::array<std::byte, 16> nonce{};
    uint64_t ciphertext_length = 0;
};

struct Container {
    ContainerHeader header;
    std::vector<std::byte> ciphertext;
};

std::vector<std::byte> serialize_container(const Container& c);
Container deserialize_container(const std::vector<std::byte>& data);
void save_container(const Container& c, const std::string& path);
Container load_container(const std::string& path);

}  // namespace aes
