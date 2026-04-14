#include "../include/crypto/CryptoRandom.h"

#include <stdexcept>

#ifdef _WIN32
#include <Windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#elif defined(__linux__)
static_assert(false, "Platform not supported: implement CryptoRandom"); // TODO : a bit important
#else
#error
static_assert(false, "Platform not supported: implement CryptoRandom");
#endif


void CryptoRandom::fill(std::span<uint8_t> buffer) {
#ifdef _WIN32
    NTSTATUS status = BCryptGenRandom(
        nullptr,
        buffer.data(),
        static_cast<ULONG>(buffer.size()),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );
    if (!BCRYPT_SUCCESS(status))
        throw std::runtime_error("BCryptGenRandom failed"); // TODO remplace with Logging method
#elif defined(__linux__)
    if (getrandom(buffer.data(), buffer.size(), 0) < 0)
        throw std::runtime_error("getrandom failed");
#else
    static_assert(false, "Platform not supported: implement CryptoRandom");
#endif
}
