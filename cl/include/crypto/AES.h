#pragma once
#include "../utils/SafeArray.h"
#include <concepts>

template <size_t N>
    requires(N == 128 || N == 192 || N == 256)
class AES {
    static constexpr size_t KEY_SIZE = N / 8; // 16 - 24 - 32
    static constexpr size_t NR = (N / 32) + 6;
    static constexpr size_t NK = N / 32;
    static constexpr size_t EXP_KEY_WORDS = (NR + 1) * 4;
    static constexpr size_t EXP_KEY_BYTES = EXP_KEY_WORDS * 4;
public:
    using Key = SafeArray<KEY_SIZE>;

    AES(const Key& key);
    ~AES() {
        m_rkey.clear();
        m_rkey_inv.clear();
    }

    void encrypt(std::span<const uint8_t> in, std::vector<uint8_t>& out);
    bool decrypt(std::span<const uint8_t> in, std::vector<uint8_t>& out);

    template<size_t BLOCKS = 1>
        requires (BLOCKS == 1 || BLOCKS == 2 || BLOCKS == 4 || BLOCKS == 8)
    void encrypt_block(std::span<uint8_t, BLOCKS * 16> block);

    template<size_t BLOCKS = 1>
        requires (BLOCKS == 1 || BLOCKS == 2 || BLOCKS == 4 || BLOCKS == 8)
    void decrypt_block(std::span<uint8_t, BLOCKS * 16> block);
private:
    SafeArray<EXP_KEY_BYTES> m_rkey;
    SafeArray<EXP_KEY_BYTES> m_rkey_inv;

    template<size_t BLOCKS>
        requires (BLOCKS == 2 || BLOCKS == 4 || BLOCKS == 8 || BLOCKS == 16)
    void cipher_vaes256(const uint8_t* in, uint8_t* out);    
    template<size_t BLOCKS>
        requires (BLOCKS == 4 || BLOCKS == 8 || BLOCKS == 16)
    void cipher_vaes512(const uint8_t* in, uint8_t* out);

    template<size_t BLOCKS>
        requires (BLOCKS == 1 || BLOCKS == 2 || BLOCKS == 4 || BLOCKS == 8)
    void cipher_aesni(const uint8_t* in, uint8_t* out);
    template<size_t BLOCKS>
        requires (BLOCKS == 1 || BLOCKS == 2 || BLOCKS == 4 || BLOCKS == 8)
    void cipher_aesni_inv(const uint8_t* in, uint8_t* out);

    void cipher(std::span<uint8_t, 16> block); // Don't really care 
    void cipher_inv(std::span<uint8_t, 16> block);
};
