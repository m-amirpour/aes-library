#include "aes/secure_memory.hpp"
#include "platform/platform.hpp"

namespace aes {
void secure_zero(void* ptr, std::size_t len) noexcept { platform::secure_zero(ptr, len); }
bool lock_memory(void* ptr, std::size_t len) noexcept { return platform::lock_memory(ptr, len); }
void unlock_memory(void* ptr, std::size_t len) noexcept { platform::unlock_memory(ptr, len); }
} // namespace aes