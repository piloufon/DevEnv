#pragma once
#include <span>
#include <vector>
#include "../utils/SafeArray.h"

template <size_t N>
    requires(N == 128 || N == 192 || N == 256)
class GCM_AES {
    static constexpr size_t KEY_SIZE = N / 8; // 16 - 24 - 32
    static constexpr size_t NR = (N / 32) + 6;
    static constexpr size_t NK = N / 32;
    static constexpr size_t EXP_KEY_WORDS = (NR + 1) * 4;
    static constexpr size_t EXP_KEY_BYTES = EXP_KEY_WORDS * 4;
    static constexpr size_t H_SIZE = 16;
    static constexpr size_t H_POWER_SIZE = H_SIZE * 4; // For now 4 is the max batched, but if it change it, it's here too
public:
    using Key = SafeArray<KEY_SIZE>;

    GCM_AES(const Key& key);
    ~GCM_AES() {
        m_rkey.clear();
    }

    static const char* get_error_message(size_t err);

    size_t verify_tag(std::span<const uint8_t> ciphertext, std::span<const uint8_t> aad, std::span<const uint8_t> nonce, std::span<const uint8_t, 16> tag) const;
    size_t encrypt(std::span<const uint8_t> plaintext, std::span<const uint8_t> aad, std::span<const uint8_t> nonce, std::span<uint8_t> ciphertext, std::span<uint8_t, 16> tag, size_t counter_start = 2) const;
    size_t decrypt(std::span<const uint8_t> ciphertext, std::span<const uint8_t> aad, std::span<const uint8_t> nonce, std::span<const uint8_t, 16> tag, std::span<uint8_t> plaintext) const;
private:
    SafeArray<EXP_KEY_BYTES> m_rkey;
    SafeArray<H_POWER_SIZE> m_H_powers;
};

