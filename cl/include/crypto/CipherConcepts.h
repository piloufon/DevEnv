#pragma once
#include <concepts>

template<typename CA>
concept CipherAlgorithm = requires(CA ca, std::span<uint8_t, 16> block) {
    typename CA::Key;
    { ca.encrypt_block(block) } -> std::same_as<void>; // Return type after declaration are so weird
    { ca.decrypt_block(block) } -> std::same_as<void>; //
};