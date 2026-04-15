#pragma once
#include <array>
#include <span>
#include <vector>

#ifdef _WIN32
#include <Windows.h>
#define ClearMem(x, y) RtlSecureZeroMemory(x, y)
#elif defined(__linux__)
#define ClearMem(x, y) explicit_bzero(x, y)  // glibc
#else
#error
static_assert(false, "Platform not supported: implement ClearMem");
#endif

template <size_t N>
class SafeArray {
public:
    ~SafeArray() {
        clear();
    }


    SafeArray() {
        m_bytes.fill(0);
    }
    SafeArray(const std::array<uint8_t, N>& bytes) noexcept {
        set(bytes);
    }
    SafeArray(const SafeArray<N>& other) noexcept {
        this->m_bytes = other.m_bytes;
    }
    SafeArray(const std::vector<uint8_t>& bytes) {
        if (bytes.size() != N)
            throw "SafeArray: wrong size dumbass";
        set(std::span<const uint8_t, N>(bytes.data(), N));
    }


    void clear() noexcept { ClearMem(m_bytes.data(), m_bytes.size()); }
    uint8_t& operator[](size_t i) noexcept { return m_bytes[i]; }
    const uint8_t& operator[](size_t i) const noexcept { return m_bytes[i]; }

    void set(std::span<const uint8_t, N> bytes) noexcept { std::copy(bytes.begin(), bytes.end(), m_bytes.begin()); }
    void set(const std::array<uint8_t, N>& bytes) noexcept { m_bytes = bytes; }
    [[nodiscard]] bool set(const std::vector<uint8_t>& bytes) noexcept {
        if (bytes.size() != N)
            return false;
        std::copy(bytes.begin(), bytes.end(), m_bytes.begin());
        return true;
    }

    bool setAndClear(uint8_t* ptr, size_t len) noexcept {
        if (len != N) return false;
        std::copy(ptr, ptr + N, m_bytes.begin());
        ClearMem(ptr, len);
        return true;
    }


    uint8_t* data() noexcept { return m_bytes.data(); }
    const uint8_t* data() const noexcept { return m_bytes.data(); }

    static constexpr size_t size() noexcept { return N; }

    auto begin() noexcept { return m_bytes.begin(); }
    auto end() noexcept { return m_bytes.end(); }
    auto begin() const noexcept { return m_bytes.begin(); }
    auto end() const noexcept { return m_bytes.end(); }
private:
    std::array<uint8_t, N> m_bytes{};
};
