#pragma once

#include <cstddef>
#include <string>

namespace aes::platform {

void csprng_fill(void* buf, std::size_t len);
void secure_zero(void* ptr, std::size_t len) noexcept;
bool lock_memory(void* ptr, std::size_t len) noexcept;
void unlock_memory(void* ptr, std::size_t len) noexcept;
bool cpu_has_aesni() noexcept;
bool cpu_has_arm_aes() noexcept;
void read_file_exact(const std::string& path, void* buf, std::size_t size);
void read_file_exact(const std::string& path, void* buf, std::size_t size);

}  // namespace aes::platform
