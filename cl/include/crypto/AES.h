#pragma once
#include "../utils/SafeArray.h"
#include <concepts>

template <size_t N>
    requires(N == 128 || N == 192 || N == 256)
class AES {
    static constexpr size_t KEY_SIZE = N / 8;   
    static constexpr size_t NR = (N / 32) + 6;
    static constexpr size_t NK = N / 32;
    static constexpr size_t EXP_KEY_WORDS = (NR + 1) * 4;
    static constexpr size_t EXP_KEY_BYTES = EXP_KEY_WORDS * 4;
public:
    using Key = SafeArray<N / 8>;

    AES(const Key& key) {
        key_expansion(key);
    }
    ~AES() {
        m_rkey.clear();
    }

    void encrypt(std::span<const uint8_t> in, std::vector<uint8_t>& out);
    bool decrypt(std::span<const uint8_t> in, std::vector<uint8_t>& out);

    void encrypt_block(std::span<uint8_t, 16> block) { m_encrypt(block); }
    void decrypt_block(std::span<uint8_t, 16> block) { m_decrypt(block); }
private:
    SafeArray<EXP_KEY_BYTES> m_rkey;


    void m_encrypt(std::span<uint8_t, 16> block);
    void m_decrypt(std::span<uint8_t, 16> block);

    void key_expansion(const Key& key);
    void add_round_key(std::span<uint8_t, 16> block, size_t round);
};

