#pragma once
#include <span>
#include <vector>
#include "CipherConcepts.h"

template <CipherAlgorithm CA>
class CTR {
public:
    using Key = typename CA::Key;

    CTR(const Key& key) : m_CA(key) {}

    void encrypt(std::span<const uint8_t> in, std::vector<uint8_t>& out, std::span<const uint8_t, 12> nonce, uint32_t counterStart = 2);
    bool decrypt(std::span<const uint8_t> in, std::vector<uint8_t>& out, std::span<const uint8_t, 12> nonce, uint32_t counterStart = 2); // return true every time, just for consistancy

private:
    CA m_CA;
};