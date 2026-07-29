#pragma once
#include <span>

class CryptoRandom {
public:
    
    static size_t fill(std::span<uint8_t> buffer);
    static const char* get_error_message(size_t err);

    template<typename T>
        requires (std::is_arithmetic_v<T>)
    static T generate() {
        T value = 0;
        fill(std::span<uint8_t>(reinterpret_cast<uint8_t*>(&value), sizeof(T)));
        return value;
    }
};