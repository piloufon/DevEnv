#include "../../include/crypto/CryptoRandom.h"

#include <cstdint>

#ifdef _WIN32
#include <Windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#elif defined(__linux__)
#include <sys/random.h>
#include <cerrno>
#else
#error
static_assert(false, "Platform not supported: implement CryptoRandom");
#endif

enum ReturnValue : size_t {
    Success = 0,
    RandomSourceFailure = 1,
};

const char* CryptoRandom::get_error_message(size_t err) {
    switch (err) {
        case Success:
            return "Success";
        case RandomSourceFailure:
            return "RandomSourceFailure";
        default:
            return "Unkown";
    }
}

size_t CryptoRandom::fill(std::span<uint8_t> buffer) {
    if (buffer.empty()) {
        return Success;
    }

    #ifdef _WIN32
    NTSTATUS status = BCryptGenRandom(
        nullptr,
        buffer.data(),
        static_cast<ULONG>(buffer.size()),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );
    if (!BCRYPT_SUCCESS(status)) {
        return RandomSourceFailure;
    }
    return Success;

    #elif defined(__linux__)
    size_t filled = 0;
    while (filled < buffer.size()) {
        ssize_t ret = getrandom(buffer.data() + filled, buffer.size() - filled, 0);
        if (ret < 0) {
            if (errno == EINTR) {
                continue; // Can be interrupt bc of some bs I think (not sure)
            }
            return RandomSourceFailure;
        }
        if (ret == 0) {
            return RandomSourceFailure;
        }
        filled += static_cast<size_t>(ret);
    }
    return Success;

    #else
    static_assert(false, "Platform not supported: implement CryptoRandom");
    #endif
}