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

    [[nodiscard]] std::vector<uint8_t> encrypt(std::span<const uint8_t> in) const;
    size_t encrypt(std::span<const uint8_t> in, std::vector<uint8_t>& out) const;
    size_t encrypt(std::span<const uint8_t> in, std::span<uint8_t> out) const noexcept;

    size_t decrypt(std::span<const uint8_t> in, std::vector<uint8_t>& out) const;

    static constexpr size_t encryption_size_out(size_t in) { return (in / 16 + 1) * 16; }
    static const char* get_error_message(size_t err);
    
    // Add a non-static function that is given 16 uint8_t that check/tell/return the padding for the decryption size (a bit like encryption_size_out) -> could help for a span'ed' decryption

    private:
    SafeArray<EXP_KEY_BYTES> m_rkey;
    SafeArray<EXP_KEY_BYTES> m_rkey_inv;
};

//template class ECB_AES<128>;
//template class ECB_AES<192>;
//template class ECB_AES<256>;