#pragma once
#include "../utils/SafeArray.h"


template <size_t N>
    requires(N == 128 || N == 192 || N == 256)
class CTR_AES {
    static constexpr size_t KEY_SIZE = N / 8; // 16 - 24 - 32
    static constexpr size_t NR = (N / 32) + 6;
    static constexpr size_t NK = N / 32;
    static constexpr size_t EXP_KEY_WORDS = (NR + 1) * 4;
    static constexpr size_t EXP_KEY_BYTES = EXP_KEY_WORDS * 4;
public:
    using Key = SafeArray<KEY_SIZE>;

    CTR_AES(const Key& key);

    size_t encrypt(std::span<const uint8_t> in, std::vector<uint8_t>& out, std::span<const uint8_t, 12> nonce, uint32_t counter_start = 2) const;
    size_t encrypt(std::span<const uint8_t> in, std::span<uint8_t> out, std::span<const uint8_t, 12> nonce, uint32_t counter_start = 2) const;

    
    size_t decrypt(std::span<const uint8_t> in, std::span<uint8_t> out, std::span<const uint8_t, 12> nonce, uint32_t counter_start = 2) const {
        return encrypt(in, std::span<uint8_t>(out), nonce, counter_start);
    }
    size_t decrypt(std::span<const uint8_t> in, std::vector<uint8_t>& out, std::span<const uint8_t, 12> nonce, uint32_t counter_start = 2) const {
        return encrypt(in, out, nonce, counter_start);
    }
    

    static const char* get_error_message(size_t err);
private:
    SafeArray<EXP_KEY_BYTES> m_rkey;
};
