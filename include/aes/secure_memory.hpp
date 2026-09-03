#pragma once
#include <cstddef>
#include <new>
#include <vector>

namespace aes {

void secure_zero(void* ptr, std::size_t len) noexcept;
bool lock_memory(void* ptr, std::size_t len) noexcept;
void unlock_memory(void* ptr, std::size_t len) noexcept;

// Allocator that locks pages and zeros on free.
// Used for key material and expanded round keys.
template <typename T>
class SecureAllocator {
   public:
    using value_type = T;
    SecureAllocator() noexcept = default;
    template <typename U>
    SecureAllocator(const SecureAllocator<U>&) noexcept {}

    T* allocate(std::size_t n) {
        if (n == 0) return nullptr;
        if (n > (static_cast<std::size_t>(-1) / sizeof(T))) throw std::bad_alloc{};
        const auto bytes = n * sizeof(T);
        auto* p = static_cast<T*>(::operator new(bytes));
        lock_memory(p, bytes);
        return p;
    }

    void deallocate(T* p, std::size_t n) noexcept {
        if (!p) return;
        const auto bytes = n * sizeof(T);
        secure_zero(p, bytes);
        unlock_memory(p, bytes);
        ::operator delete(p);
    }

    template <typename U>
    bool operator==(const SecureAllocator<U>&) const noexcept {
        return true;
    }
    template <typename U>
    bool operator!=(const SecureAllocator<U>&) const noexcept {
        return false;
    }
};

using SecureBytes = std::vector<std::byte, SecureAllocator<std::byte>>;

}  // namespace aes
