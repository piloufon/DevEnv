#pragma once
#include "../utils/SafeArray.h"

template <size_t N>
    requires(N == 128 || N == 192 || N == 256)
class ECB_AES {
    static constexpr size_t KEY_SIZE = N / 8; // 16 - 24 - 32
public:
    static constexpr size_t NR = (N / 32) + 6;
    static constexpr size_t NK = N / 32;
    static constexpr size_t EXP_KEY_WORDS = (NR + 1) * 4;
    static constexpr size_t EXP_KEY_BYTES = EXP_KEY_WORDS * 4;
public:
    using Key = SafeArray<KEY_SIZE>;

    ECB_AES(const Key& key);
    ~ECB_AES() {
        m_rkey.clear();
        m_rkey_inv.clear();
    }

    void encrypt(std::span<const uint8_t> in, std::vector<uint8_t>& out);
    bool decrypt(std::span<const uint8_t> in, std::vector<uint8_t>& out);
private:
    SafeArray<EXP_KEY_BYTES> m_rkey;
    SafeArray<EXP_KEY_BYTES> m_rkey_inv;
};
