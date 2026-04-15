#pragma once
#include <span>
#include <vector>
#include <concepts>
#include <atomic>
#include <mutex>
#include "../../include/crypto/Nonce.h"

template<typename CA>
concept CipherAlgorithm = requires(CA ca, std::span<uint8_t, 16> block) {
    typename CA::Key;
    { ca.encrypt_block(block) } -> std::same_as<void>; // Return type after declaration are so weird
    { ca.decrypt_block(block) } -> std::same_as<void>; //
};

template <CipherAlgorithm CA>
class CTR {
public:
    using Key = typename CA::Key;

    CTR(const Key& key) : m_CA(key) {}

    void encrypt(std::span<const uint8_t> in, std::vector<uint8_t>& out, std::span<const uint8_t, 12> nonce, uint32_t counterStart = 2);
    void decrypt(std::span<const uint8_t> in, std::vector<uint8_t>& out, std::span<const uint8_t, 12> nonce, uint32_t counterStart = 2);

private:
    CA m_CA;
};


